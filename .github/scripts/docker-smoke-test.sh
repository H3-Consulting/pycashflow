#!/usr/bin/env bash
# Smoke-test a built PyCashFlow image end to end.
#
# Usage: .github/scripts/docker-smoke-test.sh <image> [expected-version]
#
# Set SMOKE_DB=postgres to run against a throwaway PostgreSQL container using a
# plain postgresql:// URL (the form DigitalOcean and most hosts provide)
# instead of the default SQLite file.
#
# Set SMOKE_MCP=true to start the container with MCP_ENABLED=true, which
# switches gunicorn to its ASGI worker (app.asgi). The script then also checks
# the OAuth/MCP discovery documents and that /mcp demands a bearer token.
#
# Starts the container with a bootstrap admin, waits for /healthz, then logs in
# through the real login form (CSRF token included) and loads the dashboard.
# That exercises the entrypoint, Alembic migrations, gunicorn, auth, and the
# projection engine inside the shipped image. When expected-version is given,
# also checks that the version baked in via the DOCKER_TAG build arg matches.
set -euo pipefail

IMAGE="${1:?usage: $0 <image> [expected-version]}"
EXPECTED_VERSION="${2:-}"
NAME="pycashflow-smoke-$$"
PG_NAME="pycashflow-smoke-pg-$$"
NETWORK="pycashflow-smoke-net-$$"
SMOKE_DB="${SMOKE_DB:-sqlite}"
SMOKE_MCP="${SMOKE_MCP:-false}"
PORT="${SMOKE_PORT:-5055}"
ADMIN_EMAIL="smoke-admin@example.com"
ADMIN_PASSWORD="Smoke-Test-Passw0rd"
WORKDIR="$(mktemp -d)"
JAR="${WORKDIR}/cookies.txt"

cleanup() {
    status=$?
    if [ "${status}" -ne 0 ]; then
        echo "::group::Container logs"
        docker logs "${NAME}" 2>&1 || true
        echo "::endgroup::"
    fi
    docker rm -f "${NAME}" "${PG_NAME}" >/dev/null 2>&1 || true
    docker network rm "${NETWORK}" >/dev/null 2>&1 || true
    rm -rf "${WORKDIR}"
    exit "${status}"
}
trap cleanup EXIT

if [ -n "${EXPECTED_VERSION}" ]; then
    baked="$(docker run --rm --entrypoint printenv "${IMAGE}" APP_VERSION)"
    if [ "${baked}" != "${EXPECTED_VERSION}" ]; then
        echo "APP_VERSION in image is '${baked}', expected '${EXPECTED_VERSION}'" >&2
        exit 1
    fi
    echo "Image reports APP_VERSION=${baked}"
fi

DB_ARGS=()
case "${SMOKE_DB}" in
    sqlite) ;;
    postgres)
        docker network create "${NETWORK}" >/dev/null
        docker run -d --name "${PG_NAME}" --network "${NETWORK}" \
            -e POSTGRES_USER=smoke -e POSTGRES_PASSWORD=smoke -e POSTGRES_DB=pycashflow \
            "${SMOKE_POSTGRES_IMAGE:-postgres:17-alpine}" >/dev/null
        echo "Waiting for PostgreSQL ..."
        for _ in $(seq 1 30); do
            docker exec "${PG_NAME}" pg_isready -h 127.0.0.1 -U smoke -d pycashflow >/dev/null 2>&1 && break
            sleep 1
        done
        docker exec "${PG_NAME}" pg_isready -h 127.0.0.1 -U smoke -d pycashflow >/dev/null \
            || { echo "PostgreSQL never became ready" >&2; exit 1; }
        DB_ARGS=(--network "${NETWORK}"
                 -e "DATABASE_URL=postgresql://smoke:smoke@${PG_NAME}:5432/pycashflow")
        ;;
    *) echo "Unknown SMOKE_DB '${SMOKE_DB}' (expected sqlite or postgres)" >&2; exit 1 ;;
esac
echo "Smoke-testing ${IMAGE} with ${SMOKE_DB} (MCP enabled: ${SMOKE_MCP})"

MCP_ARGS=()
if [ "${SMOKE_MCP}" = "true" ]; then
    MCP_ARGS=(-e MCP_ENABLED=true -e "MCP_PUBLIC_BASE_URL=http://127.0.0.1:${PORT}")
fi

docker run -d --name "${NAME}" -p "127.0.0.1:${PORT}:5000" "${DB_ARGS[@]}" "${MCP_ARGS[@]}" \
    -e SECRET_KEY="smoke-test-secret-key-0123456789abcdef" \
    -e APP_SECRET="smoke-test-app-secret-0123456789abcdef" \
    -e SESSION_COOKIE_SECURE=false \
    -e TRUSTED_PROXY_COUNT=0 \
    -e ENABLE_CRON=false \
    -e BOOTSTRAP_ADMIN_EMAIL="${ADMIN_EMAIL}" \
    -e BOOTSTRAP_ADMIN_PASSWORD="${ADMIN_PASSWORD}" \
    "${IMAGE}" >/dev/null

BASE="http://127.0.0.1:${PORT}"

echo "Waiting for ${BASE}/healthz ..."
for _ in $(seq 1 60); do
    if [ "$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/healthz" || true)" = "200" ]; then
        break
    fi
    if [ "$(docker inspect -f '{{.State.Running}}' "${NAME}")" != "true" ]; then
        echo "Container exited before becoming healthy" >&2
        exit 1
    fi
    sleep 2
done
[ "$(curl -s "${BASE}/healthz")" = "ok" ] || { echo "/healthz never returned ok" >&2; exit 1; }
echo "Health check passed"

if [ "${SMOKE_MCP}" = "true" ]; then
    docker logs "${NAME}" 2>&1 | grep -q "Starting Gunicorn (ASGI, MCP enabled)" \
        || { echo "Container did not start the ASGI (MCP) server" >&2; exit 1; }
    prm="$(curl -s "${BASE}/.well-known/oauth-protected-resource/mcp")"
    printf '%s' "${prm}" | grep -q "\"resource\": *\"${BASE}/mcp\"" \
        || { echo "Protected resource metadata is wrong: ${prm}" >&2; exit 1; }
    curl -s "${BASE}/.well-known/oauth-authorization-server" | grep -q '"code_challenge_methods_supported": *\["S256"\]' \
        || { echo "Authorization server metadata is wrong" >&2; exit 1; }
    headers="$(curl -s -o /dev/null -D - -X POST -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' \
        --data '{"jsonrpc":"2.0","id":1,"method":"ping"}' "${BASE}/mcp")"
    printf '%s' "${headers}" | head -n1 | grep -q " 401" \
        || { echo "/mcp did not require authentication" >&2; exit 1; }
    printf '%s' "${headers}" | grep -qi '^www-authenticate: Bearer resource_metadata=' \
        || { echo "/mcp 401 lacks the resource_metadata challenge" >&2; exit 1; }
    echo "MCP endpoint and OAuth discovery checks passed"
else
    code="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/.well-known/oauth-authorization-server")"
    [ "${code}" = "404" ] || { echo "OAuth metadata must not exist when MCP is disabled (got ${code})" >&2; exit 1; }
fi

# Unauthenticated dashboard access must bounce to the login page.
code="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/")"
[ "${code}" = "302" ] || { echo "Expected 302 from / when logged out, got ${code}" >&2; exit 1; }

# Log in through the real form, including the CSRF token.
login_page="$(curl -s -c "${JAR}" -b "${JAR}" "${BASE}/login")"
csrf="$(printf '%s' "${login_page}" | sed -n 's/.*name="csrf_token" value="\([^"]*\)".*/\1/p' | head -n1)"
[ -n "${csrf}" ] || { echo "Could not find csrf_token on /login" >&2; exit 1; }

location="$(curl -s -o /dev/null -w '%{redirect_url}' -c "${JAR}" -b "${JAR}" \
    --data-urlencode "csrf_token=${csrf}" \
    --data-urlencode "email=${ADMIN_EMAIL}" \
    --data-urlencode "password=${ADMIN_PASSWORD}" \
    "${BASE}/login")"
case "${location}" in
    "${BASE}/") ;;
    *) echo "Login did not redirect to the dashboard (got '${location}')" >&2; exit 1 ;;
esac

dashboard="$(curl -s -w '\n%{http_code}' -c "${JAR}" -b "${JAR}" "${BASE}/")"
code="$(printf '%s' "${dashboard}" | tail -n1)"
[ "${code}" = "200" ] || { echo "Dashboard returned ${code} after login" >&2; exit 1; }
printf '%s' "${dashboard}" | grep -qi "plotly" || { echo "Dashboard did not render the cash flow chart" >&2; exit 1; }

code="$(curl -s -o /dev/null -w '%{http_code}' -c "${JAR}" -b "${JAR}" "${BASE}/settings")"
[ "${code}" = "200" ] || { echo "/settings returned ${code} after login" >&2; exit 1; }

echo "Smoke test passed for ${IMAGE} (${SMOKE_DB})"

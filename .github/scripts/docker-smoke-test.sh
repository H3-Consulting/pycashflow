#!/usr/bin/env bash
# Smoke-test a built PyCashFlow image end to end.
#
# Usage: .github/scripts/docker-smoke-test.sh <image> [expected-version]
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
    docker rm -f "${NAME}" >/dev/null 2>&1 || true
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

docker run -d --name "${NAME}" -p "127.0.0.1:${PORT}:5000" \
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

echo "Smoke test passed for ${IMAGE}"

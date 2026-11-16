#!/bin/sh

DOTENV_FILE="/app/app/.env"

# Resolve a variable from runtime environment first, then from /app/app/.env.
# Usage: get_env_or_dotenv "VAR_NAME" "default_value"
get_env_or_dotenv() {
    var_name="$1"
    default_value="$2"

    eval "runtime_value=\${${var_name}:-}"
    if [ -n "${runtime_value}" ]; then
        printf '%s' "${runtime_value}"
        return 0
    fi

    if [ -f "${DOTENV_FILE}" ]; then
        dotenv_value="$(awk -F= -v key="${var_name}" '
            $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
                sub(/^[[:space:]]*[^=]+=[[:space:]]*/, "", $0)
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
                if ($0 ~ /^"/) {
                    sub(/^"/, "", $0)
                    sub(/".*$/, "", $0)
                } else if ($0 ~ /^'\''/) {
                    sub(/^'\''/, "", $0)
                    sub(/'\''.*$/, "", $0)
                } else {
                    sub(/[[:space:]]+#.*$/, "", $0)
                }
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
                print $0
                exit
            }
        ' "${DOTENV_FILE}")"
        if [ -n "${dotenv_value}" ]; then
            printf '%s' "${dotenv_value}"
            return 0
        fi
    fi

    printf '%s' "${default_value}"
}

# Configure container local timezone from TZ env var, or /app/app/.env (defaults to UTC).
#
# Runtime env var takes precedence. If it is missing, attempt to read TZ from
# the mounted .env file so timezone configuration works even when users only
# set TZ there.
TZ_VALUE="$(get_env_or_dotenv "TZ" "UTC")"
if [ -f "/usr/share/zoneinfo/${TZ_VALUE}" ]; then
    ln -snf "/usr/share/zoneinfo/${TZ_VALUE}" /etc/localtime
    echo "${TZ_VALUE}" > /etc/timezone
else
    echo "Invalid TZ '${TZ_VALUE}', falling back to UTC."
    TZ_VALUE="UTC"
    ln -snf /usr/share/zoneinfo/UTC /etc/localtime
    echo "UTC" > /etc/timezone
fi
export TZ="${TZ_VALUE}"

# Running as root here — fix ownership of any bind-mounted volumes so
# appuser can read/write them, regardless of host directory ownership.
chown -R appuser:appgroup /app/app/data
chown -R appuser:appgroup /app/migrations
chown appuser:appgroup /app/getemail.log
# crond.log is written by root crond — leave as root:root

ENABLE_CRON_RESOLVED="$(get_env_or_dotenv "ENABLE_CRON" "true")"
ENABLE_CRON_NORMALIZED="$(printf '%s' "${ENABLE_CRON_RESOLVED}" | tr '[:upper:]' '[:lower:]')"
case "${ENABLE_CRON_NORMALIZED}" in
    true|1|yes|on)
        START_CRON=true
        ;;
    *)
        START_CRON=false
        ;;
esac

echo "ENABLE_CRON resolved to '${ENABLE_CRON_RESOLVED}' (from env/.env); cron startup: ${START_CRON}"
if [ "${START_CRON}" = "true" ]; then
    # Run crond in foreground mode (-f) so it doesn't double-fork into an
    # unreachable daemon; & sends it to the background so this script continues.
    # Daemon log goes to /app/crond.log (separate from job output in getemail.log).
    /usr/sbin/crond -f -l 8 -L /app/crond.log -c /app/crontabs/ &
fi

# Apply checked-in migrations as appuser (never generate migrations at startup)
su-exec appuser /usr/local/bin/flask --app app db upgrade

# Derive safe Gunicorn defaults (override with env vars as needed).
CPU_COUNT="$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)"
case "${CPU_COUNT}" in
    ''|*[!0-9]*|0) CPU_COUNT=1 ;;
esac
DEFAULT_GUNICORN_WORKERS=$((CPU_COUNT * 2 + 1))

# Flask-Limiter defaults to in-memory storage (memory://), which is process-local.
# Keep a single worker by default unless a shared rate-limit backend is configured.
if [ -n "${GUNICORN_WORKERS:-}" ]; then
    RESOLVED_GUNICORN_WORKERS="${GUNICORN_WORKERS}"
elif [ -z "${RATELIMIT_STORAGE_URI:-}" ]; then
    RESOLVED_GUNICORN_WORKERS=1
else
    # Treat any case/variant of memory://... as process-local storage.
    RATELIMIT_STORAGE_URI_NORMALIZED="$(printf '%s' "${RATELIMIT_STORAGE_URI}" | tr '[:upper:]' '[:lower:]')"
    case "${RATELIMIT_STORAGE_URI_NORMALIZED}" in
        memory://*) RESOLVED_GUNICORN_WORKERS=1 ;;
        *) RESOLVED_GUNICORN_WORKERS="${DEFAULT_GUNICORN_WORKERS}" ;;
    esac
fi

GUNICORN_WORKERS="${RESOLVED_GUNICORN_WORKERS}"
GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-240}"
GUNICORN_THREADS="${GUNICORN_THREADS:-8}"

MCP_ENABLED_RESOLVED="$(get_env_or_dotenv "MCP_ENABLED" "false")"
MCP_ENABLED_NORMALIZED="$(printf '%s' "${MCP_ENABLED_RESOLVED}" | tr '[:upper:]' '[:lower:]')"
case "${MCP_ENABLED_NORMALIZED}" in
    true|1|yes|on) START_MCP=true ;;
    *) START_MCP=false ;;
esac

if [ "${START_MCP}" = "true" ]; then
    # MCP integration enabled: the same gunicorn binary runs its native ASGI
    # worker. app.asgi routes /mcp to the MCP server and everything else to
    # the unchanged Flask app (run in a thread pool sized by GUNICORN_THREADS).
    # The lifespan protocol starts/stops the MCP session manager per worker.
    echo "Starting Gunicorn (ASGI, MCP enabled): workers=${GUNICORN_WORKERS}, flask threads=${GUNICORN_THREADS}, timeout=${GUNICORN_TIMEOUT}, bind=0.0.0.0:5000"
    export GUNICORN_THREADS
    exec su-exec appuser gunicorn \
        --bind 0.0.0.0:5000 \
        --workers "${GUNICORN_WORKERS}" \
        --worker-class asgi \
        --asgi-lifespan on \
        --timeout "${GUNICORN_TIMEOUT}" \
        --access-logfile - \
        --error-logfile - \
        --capture-output \
        'app.asgi:create_asgi_app()'
fi

echo "Starting Gunicorn: workers=${GUNICORN_WORKERS}, threads=${GUNICORN_THREADS}, timeout=${GUNICORN_TIMEOUT}, bind=0.0.0.0:5000"

# Run gunicorn as appuser (exec replaces the root shell — no root process remains)
exec su-exec appuser gunicorn \
    --bind 0.0.0.0:5000 \
    --workers "${GUNICORN_WORKERS}" \
    --worker-class gthread \
    --threads "${GUNICORN_THREADS}" \
    --timeout "${GUNICORN_TIMEOUT}" \
    --access-logfile - \
    --error-logfile - \
    --capture-output \
    'app:create_app()'

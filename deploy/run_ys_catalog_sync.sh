#!/bin/bash
# No environment credentials are sourced by this shell; Django reads its private .env.
set -eu
umask 077

log_result() {
    /usr/bin/printf '%s ys_catalog_sync result=%s exit_code=%s\n' "$(/usr/bin/date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" "$2"
}

case "${1:-}" in
    --cron-guard)
        # Runs without importing Django except at the four requested IST minutes.
        if [ ! -f /usr/share/zoneinfo/Asia/Kolkata ]; then
            log_result timezone_unavailable 69
            exit 69
        fi
        case "$(TZ=Asia/Kolkata /usr/bin/date +%H:%M)" in
            08:00|12:00|16:00|20:00) ;;
            *) exit 0 ;;
        esac
        ;;
    "") ;;
    *) log_result invalid_argument 64; exit 64 ;;
esac

if ! repo_dir=$(cd -- "$(/usr/bin/dirname -- "$0")/.." 2>/dev/null && pwd -P); then
    log_result repository_unavailable 72
    exit 72
fi
python_bin="$repo_dir/.venv-optix/bin/python"
if [ ! -x "$python_bin" ] || [ ! -f "$repo_dir/manage.py" ]; then
    log_result runtime_unavailable 69
    exit 69
fi
if ! /usr/bin/mkdir -p -- "$repo_dir/tmp" 2>/dev/null; then
    log_result lock_directory_unavailable 73
    exit 73
fi
cd -- "$repo_dir"
status=0
# Only a static result is logged: no Django traceback, response body or key.
# The database/admin retains sanitized per-resource error and timestamp details.
/usr/bin/flock -n -E 75 "$repo_dir/tmp/ys-catalog-sync.lock" \
    /usr/bin/timeout --signal=TERM --kill-after=10s 720s \
    "$python_bin" manage.py sync_ys_catalogs --scheduled > /dev/null 2>&1 || status=$?
if [ "$status" -eq 75 ]; then
    log_result overlap_skipped 0
    exit 0
fi
if [ "$status" -ne 0 ]; then
    log_result failed "$status"
    exit "$status"
fi
# Includes the safe no-op when YS_CATALOG_SYNC_ENABLED=false.
log_result completed_or_disabled 0

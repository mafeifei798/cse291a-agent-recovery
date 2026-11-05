#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
BIN="$ROOT/local/pgsql/bin"
DATA="$ROOT/runtime/pgdata"
mkdir -p "$ROOT/logs" "$ROOT/runtime"
[[ -x "$BIN/pg_ctl" ]] || { echo 'Run install_postgres.sh first.'; exit 1; }
TAG="$(python3 -c 'import hashlib,sys; print(hashlib.sha256(sys.argv[1].encode()).hexdigest()[:12])' "$ROOT")"
SOCKET="/tmp/cse291a-pg-$(id -u)-$TAG"
ensure_socket() {
    [[ ! -L "$SOCKET" ]] || { echo 'Socket path is a symlink; refusing.'; exit 1; }
    if [[ -e "$SOCKET" ]]; then
        [[ -d "$SOCKET" && -O "$SOCKET" ]] || { echo 'Socket directory owner/type mismatch.'; exit 1; }
    else
        (umask 077; mkdir "$SOCKET")
    fi
    chmod 700 "$SOCKET"
}
case "${1:-status}" in
  start)
    ensure_socket
    if [[ ! -f "$DATA/PG_VERSION" ]]; then
        if [[ -d "$DATA" && -n "$(ls -A "$DATA")" ]]; then
            echo 'Nonempty database directory without PG_VERSION; refusing to overwrite.'; exit 1
        fi
        "$BIN/initdb" -D "$DATA" --encoding=UTF8 --locale=C --auth-local=peer --auth-host=reject
    fi
    [[ "$(cat "$DATA/PG_VERSION")" == 16 ]] || { echo 'Unexpected database major version; no data was changed.'; exit 1; }
    if "$BIN/pg_ctl" -D "$DATA" status >/dev/null 2>&1; then
        echo 'Existing project database is running; no restart performed.'
    else
        "$BIN/pg_ctl" -D "$DATA" -l "$ROOT/logs/postgres.log" -w -t 60 \
          -o "-k '$SOCKET' -p 55432 -c listen_addresses='' -c unix_socket_permissions=0700 -c shared_preload_libraries=pg_stat_statements -c pg_stat_statements.track=all -c max_connections=20 -c shared_buffers=128MB" start
    fi
    "$BIN/psql" -X -h "$SOCKET" -p 55432 -d postgres -v ON_ERROR_STOP=1 \
       -c 'CREATE EXTENSION IF NOT EXISTS pg_stat_statements;' \
       -c 'SELECT version();' \
       -c 'SELECT count(*) AS recorded_statements FROM pg_stat_statements;'
    echo 'Smoke check passed. No benchmark workload or model call was run.'
    ;;
  stop) "$BIN/pg_ctl" -D "$DATA" -m fast -w -t 60 stop ;;
  status) "$BIN/pg_ctl" -D "$DATA" status ;;
  *) echo 'Usage: bash postgres.sh start|status|stop'; exit 2 ;;
esac

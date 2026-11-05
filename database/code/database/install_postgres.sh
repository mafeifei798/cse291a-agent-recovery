#!/usr/bin/env bash
# Installs a private PostgreSQL build; no sudo, conda, Docker, or TCP service.
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
cd "$ROOT"
mkdir -p logs downloads build local
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
exec > >(tee "logs/install_postgres_${STAMP}.log") 2>&1
[[ "$(uname -s)" == Linux ]] || { echo 'This installer targets Linux DataHub only.'; exit 1; }
[[ "$(id -u)" != 0 ]] || { echo 'Run as your normal student account.'; exit 1; }
for cmd in make perl tar gzip; do
    command -v "$cmd" >/dev/null || { echo "Missing prerequisite: $cmd. Stop and send this log."; exit 1; }
done
command -v cc >/dev/null || command -v gcc >/dev/null || { echo 'Missing C compiler.'; exit 1; }
PREFIX="$ROOT/local/pgsql"
if [[ -x "$PREFIX/bin/postgres" ]]; then
    EXISTING_VERSION="$("$PREFIX/bin/postgres" --version)"
    echo "$EXISTING_VERSION"
    [[ "$EXISTING_VERSION" == 'postgres (PostgreSQL) 16.15' ]] || { echo 'Existing install differs from 16.15; stop without overwriting it.'; exit 1; }
    echo 'Private install already exists; no rebuild or overwrite performed.'
    exit 0
fi
python3 - <<'PY'
import hashlib
from pathlib import Path
import urllib.request
version = '16.15'
name = f'postgresql-{version}.tar.gz'
base = f'https://ftp.postgresql.org/pub/source/v{version}/'
dest = Path('downloads')
for item in (name + '.sha256', name):
    path = dest / item
    if not path.exists():
        print('Downloading', base + item, flush=True)
        partial = path.with_suffix(path.suffix + '.partial')
        with urllib.request.urlopen(base + item, timeout=90) as response, partial.open('wb') as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
        partial.replace(path)
expected = (dest/(name+'.sha256')).read_text().split()[0].lower()
actual = hashlib.sha256((dest/name).read_bytes()).hexdigest()
if actual != expected:
    raise SystemExit('Source SHA256 mismatch; source will not be executed.')
print('Verified source SHA256:', actual)
PY
SOURCE="$ROOT/build/postgresql-16.15"
if [[ ! -d "$SOURCE" ]]; then
    tar -xzf downloads/postgresql-16.15.tar.gz -C build
fi
cd "$SOURCE"
# Official PostgreSQL 16 release archives include generated parser/scanner C.
# Preserve archive timestamps; do not edit grammar files or run autoreconf.
for generated in src/backend/parser/gram.c src/backend/parser/scan.c; do
    [[ -f "$generated" ]] || { echo "Missing release-generated source: $generated"; exit 1; }
done
./configure --prefix="$PREFIX" --without-readline --without-zlib --without-icu
make -j 2
make install
make -C contrib/pg_stat_statements -j 2
make -C contrib/pg_stat_statements install
"$PREFIX/bin/postgres" --version
echo 'PostgreSQL installed privately. It has not been started.'

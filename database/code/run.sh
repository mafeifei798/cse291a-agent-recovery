#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -x "$ROOT/.venv/bin/python" ]]; then
  LAB_PYTHON="$ROOT/.venv/bin/python"
elif [[ -x "$ROOT/../datahub_database_stage1/.venv/bin/python" ]]; then
  LAB_PYTHON="$ROOT/../datahub_database_stage1/.venv/bin/python"
else
  echo 'No environment found. Run bash setup.sh, or keep this folder next to stage1.' >&2
  exit 1
fi
cd "$ROOT"
if [[ "${1:-}" == test ]]; then
  shift
  exec "$LAB_PYTHON" -m unittest discover -s tests -v "$@"
fi
if [[ "${1:-}" == campaign || "${1:-}" == summarize ]]; then
  LAB_MODULE="$1"
  shift
  exec "$LAB_PYTHON" -m "dbagentlab.$LAB_MODULE" "$@"
fi
exec "$LAB_PYTHON" -m dbagentlab "$@"

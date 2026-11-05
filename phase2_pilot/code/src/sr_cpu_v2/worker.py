"""JSON CLI for a single CPU tool; process limits are set by the supervisor."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys


def _deny_network(event, args):
    if event.startswith("socket."):
        raise RuntimeError("CPU_WORKER_NETWORK_DISABLED")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec", required=True)
    parser.add_argument("--response", required=True)
    options = parser.parse_args()
    response_path = Path(options.response).resolve()
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    for name in ["OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS", "NUMEXPR_NUM_THREADS"]:
        os.environ[name] = "1"
    sys.addaudithook(_deny_network)
    try:
        # Imported only after the controller has applied affinity/address-space
        # limits. Numerical libraries use the frozen server environment.
        from .tools import execute
        spec = json.loads(Path(options.spec).read_text(encoding="utf-8"))
        response = {"ok": True, "status": "success", **execute(spec)}
        status = 0
    except Exception as exc:
        response = {"ok": False, "status": "failed", "error": {"code": getattr(exc, "code", type(exc).__name__), "message": str(exc)}}
        status = 1
    encoded = json.dumps(response, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    response_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = response_path.with_name(response_path.name + ".tmp." + str(os.getpid()))
    with temporary.open("x", encoding="utf-8") as handle:
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, response_path)
    return status


if __name__ == "__main__":
    raise SystemExit(main())

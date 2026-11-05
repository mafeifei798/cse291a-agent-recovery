#!/usr/bin/env python3
"""Read-only host checks, plus an isolated temporary C compilation probe."""
import datetime
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile


def run(argv):
    try:
        p = subprocess.run(argv, text=True, capture_output=True, timeout=20)
        return {"exit_code": p.returncode, "stdout": p.stdout[:10000],
                "stderr": p.stderr[:3000]}
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}


def main():
    root = Path(__file__).resolve().parent
    commands = {name: shutil.which(name) for name in
                ("python3", "cc", "gcc", "make", "flex", "bison", "perl",
                 "tar", "gzip", "docker", "psql", "postgres", "nvidia-smi")}
    report = {
        "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platform": platform.platform(), "machine": platform.machine(),
        "python": sys.version, "python_executable": sys.executable,
        "project_dir": str(root), "cpu_count_host_visible": os.cpu_count(),
        "disk_free_GiB": round(shutil.disk_usage(root).free / 2**30, 2),
        "commands": commands,
    }
    report["python_supported"] = (3, 10) <= sys.version_info[:2] < (3, 12)
    for label, filename in {
        "memory_cgroup_limit": "/sys/fs/cgroup/memory.max",
        "cpu_cgroup_quota": "/sys/fs/cgroup/cpu.max",
        "memory_cgroup_v1_limit": "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    }.items():
        p = Path(filename)
        if p.is_file():
            report[label] = p.read_text().strip()
    compiler = commands["cc"] or commands["gcc"]
    if compiler:
        with tempfile.TemporaryDirectory(prefix="cse291a-cc-") as directory:
            src = Path(directory) / "probe.c"
            src.write_text("#include <stdio.h>\nint main(void){puts(\"C compiler OK\");return 0;}\n")
            report["c_compile"] = run([compiler, str(src), "-o", str(Path(directory)/"probe")])
            if report["c_compile"].get("exit_code") == 0:
                report["c_execute"] = run([str(Path(directory)/"probe")])
    with tempfile.TemporaryDirectory(prefix="cse291a-venv-") as directory:
        report["venv_probe"] = run([sys.executable, "-m", "venv", str(Path(directory)/"venv")])
    if commands["nvidia-smi"]:
        report["gpu"] = run([commands["nvidia-smi"],
            "--query-gpu=name,memory.total,driver_version", "--format=csv,noheader"])
    missing = [name for name in ("make", "perl", "tar", "gzip")
               if not commands[name]]
    report["postgres_target"] = "16.15 official release tarball; flex/bison not required for unmodified release sources"
    report["postgres_build_missing_commands"] = missing
    report["postgres_build_candidate"] = bool(
        platform.system() == "Linux" and not missing
        and report.get("c_execute", {}).get("exit_code") == 0)
    folder = root / "logs"
    folder.mkdir(exist_ok=True)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = folder / ("preflight_" + stamp + ".json")
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    print("\nReport saved:", path)
    print("No model calls, installations, or database startup were performed.")


if __name__ == "__main__":
    main()

"""Tiny adverse workers for real OS resource-path acceptance, no ML or network."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--spec', type=Path, required=True)
    parser.add_argument('--response', type=Path, required=True)
    args = parser.parse_args()
    spec = json.loads(args.spec.read_text())
    tool = spec['tool']
    if tool == 'test_sleep':
        time.sleep(10)
    elif tool == 'test_term_resistant':
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        time.sleep(10)
    elif tool == 'test_child':
        child = subprocess.Popen([sys.executable, '-c', 'import time;time.sleep(10)'])
        (args.spec.parent / 'child_pid.json').write_text(json.dumps({'pid': child.pid}))
        time.sleep(10)
    elif tool == 'test_crash':
        raise RuntimeError('Expected offline resource acceptance failure')
    elif tool == 'test_allocate':
        # Small test cap is set by the parent; this does not try to use 8 GiB.
        value = bytearray(int(spec['inputs']['bytes']))
        value[0] = 1
    elif tool == 'test_file':
        with (args.spec.parent / 'oversized.bin').open('wb') as out:
            out.write(b'x' * int(spec['inputs']['bytes']))
    else:
        raise RuntimeError('Unknown resource test')
    args.response.write_text(json.dumps({'status': 'success', 'payload': {'completed': True}, 'artifacts': []}))


if __name__ == '__main__':
    main()

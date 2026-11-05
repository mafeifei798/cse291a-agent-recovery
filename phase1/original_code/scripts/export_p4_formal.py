#!/usr/bin/env python3
"""Read-only, data-only export of formal P4 evidence. Never starts a call."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from agent_recovery.p3_checker import _no_secrets


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_tables(path):
    before = sha(path)
    with sqlite3.connect(Path(path).resolve().as_uri() + '?mode=ro', uri=True) as db:
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA query_only=ON')
        if db.execute('PRAGMA integrity_check').fetchone()[0] != 'ok':
            raise ValueError('SQLite integrity failed: ' + str(path))
        names = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        tables = {name: [dict(r) for r in db.execute('SELECT * FROM "' + name.replace('"', '""') + '" ORDER BY rowid')]
                  for name in names}
    if before != sha(path):
        raise ValueError('Database changed during export: ' + str(path))
    return tables, {'sha256': before, 'bytes': Path(path).stat().st_size}


def collect(root, capsule=None):
    root = Path(root).resolve()
    artifacts, file_hashes, retained_checkpoint_hashes = {}, {}, {}
    for path in sorted(root.rglob('*')):
        if not path.is_file() or path.suffix not in ('.json', '.jsonl'):
            continue
        # The exporter output should live outside the run directory. Exclude
        # prior generated bundle copies if an operator placed one there.
        if path.name.endswith('-records.json'):
            continue
        ref = path.relative_to(root).as_posix()
        raw = path.read_bytes()
        if ref.startswith('standard_checkpoints/'):
            retained_checkpoint_hashes[ref] = hashlib.sha256(raw).hexdigest()
            continue
        artifacts[ref] = raw.decode('utf-8') if path.suffix == '.jsonl' else json.loads(raw)
        file_hashes[ref] = hashlib.sha256(raw).hexdigest()
    databases, database_hashes = {}, {}
    for path in sorted(root.rglob('*.sqlite')):
        ref = path.relative_to(root).as_posix()
        tables, metadata = read_tables(path)
        databases[ref] = tables
        database_hashes[ref] = metadata
    source = None
    if capsule:
        capsule = Path(capsule).resolve()
        source = json.loads((capsule / 'manifest.json').read_text())
        for entry in source['files']:
            ref = Path(entry['path'])
            if ref.is_absolute() or '..' in ref.parts or sha(capsule / ref) != entry['sha256']:
                raise ValueError('Source capsule mismatch: ' + str(ref))
        for name in ('process_exit.json', 'driver_pid.json'):
            path = capsule / name
            if path.is_file():
                artifacts['capsule/' + name] = json.loads(path.read_text())
    result = {'schema_version': 'p4-formal-records-v1', 'artifacts': artifacts,
        'artifact_file_sha256': file_hashes, 'databases': databases,
        'database_hashes': database_hashes, 'source_manifest': source,
        'binary_databases_remain_in_DataHub': True,
        'export_read_only': True,
        'retained_checkpoint_file_sha256': retained_checkpoint_hashes,
        'checkpoint_history_remains_in_DataHub': True}
    _no_secrets(result)
    return result


def export(root, capsule, destination):
    destination = Path(destination)
    if destination.exists():
        raise ValueError('Refusing to overwrite export')
    result = collect(root, capsule)
    destination.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
    out = {'schema_version': 'p4-export-receipt-v1', 'file': destination.name,
        'sha256': sha(destination), 'bytes': destination.stat().st_size,
        'artifacts': len(result['artifacts']), 'databases': len(result['databases']),
        'binary_databases_remain_in_DataHub': True, 'new_api_calls': 0}
    destination.with_name(destination.stem + '-export.json').write_text(json.dumps(out, indent=2) + '\n')
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run-root', required=True)
    parser.add_argument('--capsule-root')
    parser.add_argument('--destination', required=True)
    args = parser.parse_args()
    print(json.dumps(export(args.run_root, args.capsule_root, args.destination)))


if __name__ == '__main__':
    main()

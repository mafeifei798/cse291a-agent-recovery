"""Append-only evidence, conservative dependencies, and shared run budgets."""
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import time


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, default=str).encode()


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('wb') as stream:
        stream.write(encode(value) + b'\n')
        stream.flush()
        os.fsync(stream.fileno())
    temporary.replace(path)


def new_id(prefix):
    return prefix + '_' + secrets.token_hex(6)


class BudgetExceeded(RuntimeError):
    pass


class Budget:
    """One ledger across initial work AND full restart; no automatic reset."""
    def __init__(self, max_calls=36, max_seconds=900):
        self.max_calls = max_calls
        self.max_seconds = max_seconds
        self.started = time.monotonic()
        self.calls = 0

    def remaining(self):
        remaining = self.max_seconds - (time.monotonic() - self.started)
        if remaining <= 0:
            raise BudgetExceeded('Shared wall-time budget exhausted')
        return remaining

    def reserve(self):
        self.remaining()
        if self.calls >= self.max_calls:
            raise BudgetExceeded('Shared model-call budget exhausted; no request sent')
        self.calls += 1


class Ledger:
    """Single-process event journal; atomic artifacts; logs never become prompts wholesale."""
    def __init__(self, folder, secret=''):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=False)
        os.chmod(self.folder, 0o700)
        self.secret = secret
        self.artifacts = {}
        self.events = []

    def redact(self, value):
        if isinstance(value, str):
            return value.replace(self.secret, '[REDACTED]') if self.secret else value
        if isinstance(value, dict):
            return {k: self.redact(v) for k, v in value.items()}
        if isinstance(value, (tuple, list)):
            return [self.redact(v) for v in value]
        return value

    def write(self, relative, value):
        save(self.folder / relative, self.redact(value))

    def event(self, kind, **fields):
        event = self.redact({'event_id': new_id('evt'), 'utc': utc(), 'kind': kind, **fields})
        with (self.folder / 'events.jsonl').open('ab') as stream:
            stream.write(encode(event) + b'\n')
            stream.flush()
            os.fsync(stream.fileno())
        self.events.append(event)
        return event['event_id']

    def artifact(self, kind, actor, payload, parents=(), branch='initial', **metadata):
        parents = list(dict.fromkeys(parents))
        unknown = set(parents) - self.artifacts.keys()
        if unknown:
            raise ValueError('Unknown dependency IDs: ' + str(sorted(unknown)))
        identifier = new_id(kind)
        artifact = self.redact({'id': identifier, 'kind': kind, 'actor': actor,
            'branch': branch, 'created': utc(), 'parents': parents, 'payload': payload, **metadata})
        artifact['sha256'] = hashlib.sha256(encode(artifact)).hexdigest()
        self.write('artifacts/' + identifier + '.json', artifact)
        self.artifacts[identifier] = artifact
        self.event('artifact_created', artifact_id=identifier, parents=parents, actor=actor, branch=branch)
        return artifact

    def descendants(self, identifier):
        affected = {identifier}
        for key, artifact in self.artifacts.items():
            if set(artifact['parents']) & affected:
                affected.add(key)
        return affected - {identifier}

    def export_graph(self):
        self.write('dependencies.json', {
            'semantics': 'Conservative exposure graph, NOT proof of semantic influence. '
                         'Every artifact supplied in an actor history is a potential dependency.',
            'nodes': list(self.artifacts.values())})

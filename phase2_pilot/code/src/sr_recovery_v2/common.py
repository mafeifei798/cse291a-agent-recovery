"""Small deterministic protocol primitives. No clients, training or network IO."""
import hashlib
import json
from datetime import datetime, timezone

REV = 'sr-v2-v0-r1'


class ProtocolError(RuntimeError):
    def __init__(self, code, message=None):
        self.code = code
        super().__init__(message or code)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode('utf-8')).hexdigest()


def source_fingerprint(sources):
    return digest(sorted([{'object_key': s['object_key'], 'version': s['version'],
                           'payload_digest': s['payload_digest']} for s in sources],
                         key=lambda s: s['object_key']))


def selected_graph_digest(selected, results):
    return digest({'selected_by_node': selected, 'results': results})


def read_refs(sources):
    return sorted([{'object_key': s['object_key'], 'version': s['version']} for s in sources],
                  key=lambda s: s['object_key'])


def closure_ids(seeds, results):
    found = set(seeds)
    while True:
        expanded = found | {r['result_id'] for r in results if found.intersection(r['parent_result_ids'])}
        if expanded == found:
            return sorted(found)
        found = expanded


def merge_reads(groups):
    values = {}
    for group in groups:
        for ref in group:
            key, version = ref['object_key'], ref['version']
            if key in values and values[key] != version:
                raise ProtocolError('PROVABLE_MIXED_READ_VERSIONS')
            values[key] = version
    return [{'object_key': key, 'version': values[key]} for key in sorted(values)]


def node_map(dag):
    return {node['node_id']: node for node in dag['nodes']}


def utc_parse(text):
    value = datetime.fromisoformat(text.replace('Z', '+00:00'))
    if value.tzinfo is None or value.utcoffset().total_seconds() != 0:
        raise ProtocolError('UTC_TIMESTAMP_REQUIRED')
    return value.astimezone(timezone.utc)


def utc_format(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

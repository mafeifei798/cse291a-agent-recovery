"""Small durable file/provenance adapter for the development pilot.

The inherited SQLite writer transaction is the acceptance boundary. File names
are logical keys, never paths to overwrite; content-addressed UTF-8 blobs are
staged before acceptance, as in V1Store. This is not a general filesystem
sandbox or a claim of an atomic filesystem/SQLite distributed transaction.
"""
from copy import deepcopy
import json
import os
from pathlib import Path, PurePosixPath
import stat

from agent_recovery.recovery_store import backup_database
from sr_recovery_v2.common import ProtocolError, canonical, closure_ids
from sr_recovery_v2.store import V1Store

from .contracts import byte_hash, require


class FileProvenanceStore(V1Store):
    """Versioned logical files and append-only observed result nodes."""

    REF_FIELDS = {'file_id', 'version', 'sha256', 'writer_id'}

    def __init__(self, db_path, artifact_root):
        # Check before V1Store resolves paths, so a supplied symlink cannot be
        # silently converted into its target. Recheck when accessing blobs.
        self._no_symlinks(Path(db_path).absolute())
        self._no_symlinks(Path(artifact_root).absolute())
        super().__init__(db_path, artifact_root)
        self._blob_root = self.artifact_root / 'sha256'
        self._no_symlinks(self._blob_root)
        self._blob_root.mkdir(exist_ok=True)
        self.db.executescript('''
            CREATE TABLE IF NOT EXISTS ctx_files (
                file_id TEXT PRIMARY KEY, ref TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS ctx_file_history (
                file_id TEXT NOT NULL, version INTEGER NOT NULL,
                ref TEXT NOT NULL, PRIMARY KEY(file_id, version));
            CREATE TABLE IF NOT EXISTS ctx_nodes (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                result_id TEXT UNIQUE NOT NULL, payload TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS ctx_events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL);
        ''')

    @staticmethod
    def _no_symlinks(path):
        for entry in (path, *path.parents):
            # macOS exposes its real temporary directory through /var and
            # /tmp. Only these exact OS aliases are accepted; a symlink below
            # them, including the caller's root itself, is still refused.
            system_alias = (str(entry) in ('/var', '/tmp', '/etc')
                            and entry.resolve() == Path('/private') / entry.name)
            require(not entry.is_symlink() or system_alias, 'FILE_SYMLINK_FORBIDDEN')

    @staticmethod
    def _key(key):
        require(isinstance(key, str) and bool(key) and '\\' not in key
                and '\x00' not in key, 'FILE_KEY_INVALID')
        parts = key.split('/')
        require(not PurePosixPath(key).is_absolute()
                and all(part not in ('', '.', '..') for part in parts), 'FILE_KEY_INVALID')
        return key

    @classmethod
    def _check_ref(cls, ref):
        require(isinstance(ref, dict) and set(ref) == cls.REF_FIELDS,
                'FILE_REFERENCE_INVALID')
        cls._key(ref['file_id'])
        require(type(ref['version']) is int and ref['version'] > 0
                and isinstance(ref['writer_id'], str) and bool(ref['writer_id'])
                and isinstance(ref['sha256'], str) and len(ref['sha256']) == 64
                and all(c in '0123456789abcdef' for c in ref['sha256']),
                'FILE_REFERENCE_INVALID')

    def _blob_path(self, sha256):
        require(isinstance(sha256, str) and len(sha256) == 64
                and all(c in '0123456789abcdef' for c in sha256), 'FILE_HASH_INVALID')
        path = self._blob_root / sha256
        self._no_symlinks(path)
        require(path.parent == self._blob_root and self._blob_root.parent == self.artifact_root,
                'FILE_PATH_ESCAPE')
        return path

    def _content(self, ref):
        self._check_ref(ref)
        path = self._blob_path(ref['sha256'])
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(fd, 'rb') as handle:
                require(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), 'FILE_BLOB_INVALID')
                content = handle.read()
        except OSError as exc:
            raise ProtocolError('FILE_BLOB_MISSING') from exc
        require(byte_hash(content) == ref['sha256'], 'FILE_CONTENT_TAMPERED')
        try:
            return content.decode('utf-8')
        except UnicodeDecodeError as exc:
            raise ProtocolError('FILE_CONTENT_TAMPERED') from exc

    def _stage(self, content):
        require(isinstance(content, str), 'FILE_CONTENT_TYPE')
        value = content.encode('utf-8')
        sha256 = byte_hash(value)
        path = self._blob_path(sha256)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        except FileExistsError:
            # A hash match is insufficient if existing bytes were changed.
            self._content({'file_id': 'blob', 'version': 1, 'sha256': sha256,
                           'writer_id': 'blob-check'})
        else:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(value)
                handle.flush()
                os.fsync(handle.fileno())
            directory = os.open(self._blob_root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        return sha256

    def _current(self, key):
        row = self.db.execute('SELECT ref FROM ctx_files WHERE file_id=?', (key,)).fetchone()
        return json.loads(row[0]) if row else None

    def _event(self, kind, **details):
        cursor = self.db.execute('INSERT INTO ctx_events(payload) VALUES(?)',
                                 (canonical({'kind': kind, **details}),))
        return cursor.lastrowid

    def initialize(self, key, content, writer='bootstrap'):
        return self.write(key, content, expected=None, writer_id=writer)['after']

    def read(self, key):
        key = self._key(key)
        with self._transaction():
            ref = self._current(key)
            require(ref is not None, 'FILE_NOT_FOUND')
            return {**ref, 'content': self._content(ref)}

    def _write(self, key, content, expected, writer_id, restore_ref=None, read_set=()):
        key = self._key(key)
        require(isinstance(content, str), 'FILE_CONTENT_TYPE')
        require(isinstance(writer_id, str) and bool(writer_id), 'FILE_WRITER_INVALID')
        if expected is not None:
            self._check_ref(expected)
            require(expected['file_id'] == key, 'FILE_REFERENCE_INVALID')
        if restore_ref is not None:
            self._check_ref(restore_ref)
            require(restore_ref['file_id'] == key, 'FILE_REFERENCE_INVALID')
        require(isinstance(read_set,(list,tuple)),'FILE_READ_SET_INVALID')
        for ref in read_set:self._check_ref(ref)
        require(len({r['file_id'] for r in read_set})==len(read_set),'FILE_READ_SET_INVALID')
        conflict = False
        external_owner = False
        result = None
        with self._transaction():
            before = self._current(key)
            if before is not None:
                self._content(before)
            stale_reads=[ref for ref in read_set if self._current(ref['file_id'])!=ref]
            if stale_reads:
                self._event('file_input_conflict',file_id=key,writer_id=writer_id,
                    expected_reads=list(read_set),stale_reads=stale_reads)
                conflict=True
            elif before != expected:
                # Commit refusal evidence, then raise after the transaction.
                self._event('file_restore_conflict' if restore_ref else 'file_write_conflict',
                            file_id=key, expected=expected, actual=before,
                            writer_id=writer_id, restore_ref=restore_ref)
                conflict = True
            elif (restore_ref is not None and before is not None
                  and (before['writer_id'] == 'external'
                       or before['writer_id'].startswith('external-'))):
                # Knowing the latest version does not grant ownership of an
                # independent writer's update. This bounded pilot convention
                # protects external source updates and consumption receipts.
                self._event('file_restore_external_owner', file_id=key,
                            expected=expected, actual=before, writer_id=writer_id,
                            restore_ref=restore_ref, refusal_code='FILE_EXTERNAL_OWNER')
                external_owner = True
            else:
                if restore_ref is not None:
                    saved = self.db.execute('SELECT ref FROM ctx_file_history '
                                            'WHERE file_id=? AND version=?',
                                            (key, restore_ref['version'])).fetchone()
                    require(saved is not None and json.loads(saved[0]) == restore_ref,
                            'FILE_RESTORE_REFERENCE_UNKNOWN')
                    content = self._content(restore_ref)
                sha256 = self._stage(content)
                after = {'file_id': key, 'version': before['version'] + 1 if before else 1,
                         'sha256': sha256, 'writer_id': writer_id}
                self.db.execute('INSERT INTO ctx_files VALUES(?,?) ON CONFLICT(file_id) '
                                'DO UPDATE SET ref=excluded.ref', (key, canonical(after)))
                self.db.execute('INSERT INTO ctx_file_history VALUES(?,?,?)',
                                (key, after['version'], canonical(after)))
                self._event('file_restore' if restore_ref else 'file_write',
                            file_id=key, before=before, after=after, restore_ref=restore_ref)
                result = {'before': before, 'after': after}
        if conflict:
            raise ProtocolError('FILE_VERSION_CONFLICT')
        if external_owner:
            raise ProtocolError('FILE_EXTERNAL_OWNER')
        return deepcopy(result)

    def write(self, key, content, expected, writer_id):
        return self._write(key, content, expected, writer_id)

    def write_checked(self,key,content,expected,writer_id,read_set):
        """Compare the whole guard read-set in the same transaction as write."""
        return self._write(key,content,expected,writer_id,read_set=read_set)

    def restore(self, key, expected, restore_ref, writer_id):
        # Historical content is read inside the same writer transaction that
        # compares the current version. Never reset a version counter.
        self._check_ref(restore_ref)
        return self._write(key, '', expected, writer_id, restore_ref=restore_ref)

    def record_node(self, node):
        require(isinstance(node, dict) and {'result_id', 'parent_result_ids', 'kind', 'role', 'payload'}
                <= set(node), 'NODE_FIELDS')
        require(isinstance(node['result_id'], str) and bool(node['result_id'])
                and isinstance(node['parent_result_ids'], list)
                and all(isinstance(p, str) and p for p in node['parent_result_ids'])
                and len(set(node['parent_result_ids'])) == len(node['parent_result_ids'])
                and node['result_id'] not in node['parent_result_ids']
                and isinstance(node['kind'], str) and bool(node['kind'])
                and isinstance(node['role'], str) and bool(node['role']), 'NODE_FIELDS')
        body = canonical(node)
        with self._transaction():
            old = self.db.execute('SELECT payload FROM ctx_nodes WHERE result_id=?',
                                  (node['result_id'],)).fetchone()
            if old:
                require(old[0] == body, 'IMMUTABLE_NODE_ID')
                return json.loads(old[0])
            for parent in node['parent_result_ids']:
                require(self.db.execute('SELECT 1 FROM ctx_nodes WHERE result_id=?',
                                        (parent,)).fetchone() is not None, 'NODE_PARENT_UNKNOWN')
            self.db.execute('INSERT INTO ctx_nodes(result_id,payload) VALUES(?,?)',
                            (node['result_id'], body))
            self._event('node_recorded', result_id=node['result_id'])
        return json.loads(body)

    def _snapshot(self):
        files = {key: json.loads(ref) for key, ref in
                 self.db.execute('SELECT file_id,ref FROM ctx_files ORDER BY file_id')}
        history = [json.loads(row[0]) for row in self.db.execute(
            'SELECT ref FROM ctx_file_history ORDER BY file_id,version')]
        # Snapshot/export must not silently bless changed historical bytes.
        for ref in history:
            self._content(ref)
        return {'files': files, 'file_history': history,
                'nodes': [json.loads(row[0]) for row in self.db.execute(
                    'SELECT payload FROM ctx_nodes ORDER BY seq')],
                'events': [{'event_seq': seq, **json.loads(payload)} for seq, payload in
                           self.db.execute('SELECT seq,payload FROM ctx_events ORDER BY seq')]}

    def snapshot(self):
        with self._transaction():
            return self._snapshot()

    def graph_closure(self, seeds):
        return closure_ids(seeds, self.snapshot()['nodes'])

    def save_to(self, destination):
        destination = Path(destination).absolute()
        self._no_symlinks(destination)
        require(not destination.exists(), 'STORE_EXPORT_EXISTS')
        # Independent read-only backup sees the same committed state while
        # BEGIN IMMEDIATE prevents another writer from changing the source.
        with self._transaction():
            snapshot = self._snapshot()
            destination.mkdir(parents=True)
            backup_database(self.db_path, destination / 'store.sqlite')
            blobs = destination / 'artifacts' / 'sha256'
            blobs.mkdir(parents=True)
            refs = {r['sha256']: r for r in snapshot['file_history']}
            for sha256 in sorted(refs):
                (blobs / sha256).write_text(self._content(refs[sha256]), encoding='utf-8')
            (destination / 'snapshot.json').write_text(
                json.dumps(snapshot, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        return snapshot

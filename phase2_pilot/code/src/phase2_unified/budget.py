"""Durable simulated ledger. Never acquires or mutates a live budget authority.

The historical balance is a pinned read-only carry, not permission to spend it.
All new amounts and dispatches below are explicitly synthetic.
"""
import fcntl
import json
from pathlib import Path
import sqlite3
import time

from phase2_offline.common import canonical, digest, require

LIMITS = dict(project_nano=5_000_000_000, campaign_nano=2_500_000_000,
              batch_nano=1_000_000_000, campaign_calls=1180, batch_calls=460,
              call_reservation_nano=1_924_000, pacing_ns=2_000_000_000,
              prompt_token_cap=4000, completion_token_cap=2048)
HISTORY = dict(known_nano=179_686_100, held_nano=3_252_000)
OTHER_PLANNED_CAP_NANO = 1_500_000_000  # original 72 rows, planned, never billed


class VirtualClock:
    """Logical pacing clock; never represent its waits as measured API latency."""
    def __init__(self, value=0):
        self.value = value
    def now(self):
        return self.value
    def wait(self, nanoseconds):
        self.value += nanoseconds


class Ledger:
    def __init__(self, path, rows, pack_digest, *, limits=None):
        if limits is not None:
            require(set(limits) == set(LIMITS), 'INVALID_LIMIT_KEYS')
            for name, value in limits.items():
                require(type(value) is int and value >= 0, 'INVALID_LIMIT_VALUE')
                if name == 'pacing_ns':
                    require(value >= LIMITS[name], 'PACING_CANNOT_BE_WEAKENED')
                else:
                    require(value <= LIMITS[name], 'LIMIT_CANNOT_BE_RAISED')
        self.registry = {r['row_id']: dict(r) for r in rows}
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = self.path.with_suffix(".lock").open("a+")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close()
            raise ValueError("CAMPAIGN_ALREADY_LOCKED")
        self.db = sqlite3.connect(self.path)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute("CREATE TABLE IF NOT EXISTS document (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)")
        found = self.db.execute("SELECT body FROM document WHERE id=1").fetchone()
        if found is None:
            self.state = dict(mode="offline_fixture", fixture_only=True, real_api_calls=0,
                pack_digest=pack_digest, limits=limits or LIMITS.copy(), history=HISTORY.copy(),
                rows=[dict(row_id=r['row_id'], batch_id=r['batch_id'], call_cap=r['call_cap'],
                    status="not_started", run_count=0, result_sha256=None) for r in rows],
                calls=[], events=[], stopped_reason=None, last_response_ns=None, checkpoints=[])
            self._commit("initialized")
        else:
            self.state = json.loads(found[0])
            try:
                require(self.state['pack_digest'] == pack_digest, "PACK_CHANGED")
                require(self.state['limits'] == (limits or LIMITS), "LIMITS_CHANGED")
                require(self.state['history'] == HISTORY, "HISTORY_CHANGED")
                keys = ('row_id','batch_id','call_cap')
                require([{k:r[k] for k in keys} for r in self.state['rows']] ==
                        [{k:r[k] for k in keys} for r in rows], "REGISTRY_CHANGED")
            except BaseException:
                self.close()
                raise

    def close(self):
        self.db.close()
        fcntl.flock(self.lock, fcntl.LOCK_UN)
        self.lock.close()

    def _commit(self, kind, **details):
        self.state['events'].append(dict(seq=len(self.state['events'])+1, kind=kind, **details))
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO document VALUES (1, ?)", (canonical(self.state).decode(),))

    def row(self, row_id):
        return next(r for r in self.state['rows'] if r['row_id'] == row_id)

    def snapshot(self):
        value = json.loads(canonical(self.state))
        known = sum(c['known_nano'] for c in value['calls'])
        held = sum(c['held_nano'] for c in value['calls'])
        value.update(campaign_known_nano=known, campaign_held_nano=held,
            historical_known_nano=HISTORY['known_nano'], historical_held_nano=HISTORY['held_nano'],
            project_total_nano=HISTORY['known_nano']+HISTORY['held_nano']+known+held,
            simulated_dispatches=len(value['calls']), actual_new_api_cost_nano=0,
            pacing_clock="virtual_offline_only", other_planned_cap_nano=OTHER_PLANNED_CAP_NANO,
            planning_envelope_nano=HISTORY["known_nano"]+HISTORY["held_nano"]+OTHER_PLANNED_CAP_NANO+limits_campaign(self.state),
            actual_new_api_cost_nano_usd=0)
        return value

    def assert_resumable(self):
        require(self.state['stopped_reason'] is None, "CAMPAIGN_HARD_STOPPED")
        require(not any(r['status'] == 'running' for r in self.state['rows']), "UNRECONCILED_RUNNING_ROW")
        require(not any(c['status'] != 'settled' for c in self.state['calls']), "UNRECONCILED_CALL")

    def start_row(self, row_id):
        self.assert_resumable()
        row = self.row(row_id)
        require(row['status'] == 'not_started' and row['run_count'] == 0, "ROW_CANNOT_RERUN")
        row.update(status='running', run_count=1)
        self._commit('row_started', row_id=row_id)

    def finish_row(self, row_id, status, result_sha256):
        row = self.row(row_id)
        require(row['status'] == 'running', 'ROW_NOT_RUNNING')
        row.update(status=status, result_sha256=result_sha256)
        self._commit('row_finished', row_id=row_id, status=status)

    def block_row(self, row_id, result_sha256):
        row = self.row(row_id)
        require(row['status'] == 'not_started', 'ROW_CANNOT_RERUN')
        row.update(status='not_run_blocked_prefix', result_sha256=result_sha256)
        self._commit('row_blocked', row_id=row_id)

    def stop(self, reason):
        if self.state['stopped_reason'] is None:
            self.state['stopped_reason'] = reason
            self._commit('hard_stop', reason=reason)

    def reserve(self, event, clock):
        require(self.state['stopped_reason'] is None, 'CAMPAIGN_HARD_STOPPED')
        require(event.get('fixture_only') is True, 'LIVE_EVENT_FORBIDDEN')
        require(all(isinstance(event.get(k),str) and event[k] for k in
                    ('row_id','call_id','node_id','attempt_id','input_digest')), 'DISPATCH_IDENTITY_REQUIRED')
        row = self.row(event['row_id'])
        require(row['status'] == 'running', 'CALL_WITHOUT_RUNNING_ROW')
        require(not any(c['call_id'] == event['call_id'] for c in self.state['calls']), 'DUPLICATE_CALL_ID')
        require(not any(c['status'] != 'settled' for c in self.state['calls']), 'PRIOR_CALL_UNSETTLED')
        snapshot, limits = self.snapshot(), self.state['limits']
        batch = [c for c in self.state['calls'] if c['batch_id'] == row['batch_id']]
        own = [c for c in batch if c['row_id'] == row['row_id']]
        reserve = limits['call_reservation_nano']
        used = snapshot['campaign_known_nano'] + snapshot['campaign_held_nano']
        require(len(own) < row['call_cap'], 'ROW_CALL_CAP')
        registered_batch_cap = sum(r['call_cap'] for r in self.registry.values() if r['batch_id'] == row['batch_id'])
        require(len(batch) < min(limits['batch_calls'], registered_batch_cap), 'BATCH_CALL_CAP')
        require(len(self.state['calls']) < limits['campaign_calls'], 'CAMPAIGN_CALL_CAP')
        require(sum(c['known_nano']+c['held_nano'] for c in batch)+reserve <= limits['batch_nano'], 'BATCH_MONEY_CAP')
        require(used+reserve <= limits['campaign_nano'], 'CAMPAIGN_MONEY_CAP')
        require(snapshot['project_total_nano']+reserve+OTHER_PLANNED_CAP_NANO <= limits['project_nano'], 'PROJECT_MONEY_CAP')
        last = self.state['last_response_ns']
        wait = max(0, last + limits['pacing_ns'] - clock.now()) if last is not None else 0
        clock.wait(wait)
        self.state['calls'].append(dict(call_id=event['call_id'], row_id=row['row_id'],
            batch_id=row['batch_id'], node_id=event['node_id'],
            attempt_id=event['attempt_id'], input_digest=event['input_digest'], status='reserved', fixture_only=True,
            known_nano=0, held_nano=reserve, reserved_nano=reserve, usage=None,
            dispatch_at_ns=clock.now(), settled_at_ns=None, logical_wait_ns=wait,
            http_status=None, evidence_kind='synthetic_dispatch'))
        self._commit('call_reserved', call_id=event['call_id'])

    def settle(self, event, clock):
        call = next(c for c in self.state['calls'] if c['call_id'] == event['call_id'])
        require(call['status'] == 'reserved', 'CALL_ALREADY_SETTLED')
        require(event.get('fixture_only') is True, 'LIVE_EVENT_FORBIDDEN')
        require(all(call[k] == event.get(k) for k in
                    ('row_id','node_id','attempt_id','input_digest')), 'CALL_IDENTITY_MISMATCH')
        call['http_status'] = event.get('http_status', 200)
        call['settled_at_ns'] = clock.now()
        self.state['last_response_ns'] = clock.now()
        usage = event.get('usage')
        if event.get('status') == 'uncertain' or call['http_status'] == 429 or usage is None:
            call['status'] = 'uncertain'
            self.state['stopped_reason'] = 'HTTP_429' if call['http_status'] == 429 else 'UNKNOWN_USAGE'
            self._commit('call_uncertain', call_id=call['call_id'])
            return
        p, c, total = (usage.get(k) for k in ('prompt_tokens','completion_tokens','total_tokens'))
        valid = all(type(v) is int and v >= 0 for v in (p,c,total)) and p+c == total
        valid = valid and p <= self.state['limits']['prompt_token_cap'] and c <= self.state['limits']['completion_token_cap']
        if not valid:
            call['status'] = 'uncertain'
            self.state['stopped_reason'] = 'INVALID_USAGE'
            self._commit('call_uncertain', call_id=call['call_id'])
            return
        cost = p*150+c*500
        require(cost <= call['reserved_nano'], 'COST_EXCEEDS_RESERVATION')
        call.update(status='settled', usage=usage, known_nano=cost, held_nano=0)
        self._commit('call_settled', call_id=call['call_id'])

    def checkpoint(self, batch_id, audit_digest, exports_digest):
        self.assert_resumable()
        selected = [r for r in self.state['rows'] if r['batch_id'] == batch_id]
        require(all(r['status'] != 'not_started' for r in selected), 'BATCH_INCOMPLETE')
        cp = dict(batch_id=batch_id, audit_digest=audit_digest, exports_digest=exports_digest,
                  calls=len(self.state['calls']), known_nano=self.snapshot()['campaign_known_nano'])
        cp['digest'] = digest(cp)
        require(not any(c['batch_id'] == batch_id for c in self.state['checkpoints']), 'DUPLICATE_BATCH_CHECKPOINT')
        self.state['checkpoints'].append(cp)
        self._commit('batch_checkpoint', batch_id=batch_id)
        return cp


def limits_campaign(state):
    return state["limits"]["campaign_nano"]

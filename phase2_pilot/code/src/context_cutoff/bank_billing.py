"""Read-only, fail-closed key-spend reconciliation for the Bank pilot.

An observed spend delta is evidence about this receipt, not a promise about
future billing. No retry, generation, credential export, or budget mutation.
"""
from __future__ import annotations

from datetime import datetime, timezone
from decimal import Decimal
import http.client
import json
import math
import multiprocessing
import os
from pathlib import Path
import selectors
import ssl
import struct
from time import monotonic

from agent_recovery.contracts import ContractError

ENDPOINT = 'https://tritonai-api.ucsd.edu/key/info'
ERROR = 'BANK_BILLING_UNRECONCILED'
_MAX_PACKET = 8192


def datahub_environment_credential():
    """Pass this module-level provider to avoid reading a key in the parent."""
    return os.environ['OPENAI_API_KEY']


def _now():
    return datetime.now(timezone.utc).isoformat()


def _nano(value):
    if isinstance(value, bool) or value is None:
        raise ValueError('amount')
    amount = Decimal(str(value))
    if not amount.is_finite() or amount < 0:
        raise ValueError('amount')
    # Retain sub-nano precision so that rounding cannot hide a discrepancy.
    return amount * Decimal(1_000_000_000)


def _safe_snapshot(value):
    if not isinstance(value, dict):
        raise ValueError('snapshot')
    if value.get('http_status', value.get('status', 200)) != 200:
        raise ValueError('http_status')
    info = value.get('info', value)
    if not isinstance(info, dict):
        raise ValueError('info')
    spend = _nano(info.get('spend_usd', info.get('spend')))
    budget = _nano(info.get('max_budget_usd', info.get('max_budget')))
    # Only monetary amounts and a bounded timestamp/duration are exported.
    result = {'spend_nano': str(spend), 'max_budget_nano': str(budget),
              'remaining_nano': str(budget - spend), 'observed_utc': _now()}
    for field in ('budget_duration', 'budget_reset_at'):
        raw = info.get(field)
        if raw is not None and (not isinstance(raw, str) or len(raw) > 128):
            raise ValueError('reset_metadata')
        result[field] = raw
    result['reset_verified'] = result['budget_reset_at'] is not None
    return result


def _metadata_worker(connection, credential_provider, deadline):
    """Only this spawned process obtains the credential or parses raw JSON."""
    credential = None
    try:
        if hasattr(os, 'setsid'):
            os.setsid()
        credential = credential_provider()
        if not isinstance(credential, str) or not credential or '\n' in credential or '\r' in credential:
            raise ValueError('credential')
        remaining = deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError()
        client = http.client.HTTPSConnection('tritonai-api.ucsd.edu', 443,
            timeout=remaining, context=ssl.create_default_context())
        try:
            client.request('GET', '/key/info', headers={
                'Authorization': 'Bearer ' + credential, 'Accept': 'application/json'})
            response = client.getresponse()
            if response.status != 200:  # Includes redirects and 429; never retry.
                packet = {'ok': False, 'error': 'metadata_http_status',
                          'http_status': response.status}
            else:
                body = response.read(1_048_577)
                if len(body) > 1_048_576:
                    raise ValueError('response_size')
                raw = json.loads(body, parse_float=Decimal)
                snapshot = _safe_snapshot(raw)
                if credential in json.dumps(snapshot):
                    raise ValueError('credential_echo')
                packet = {'ok': True, 'snapshot': snapshot}
        finally:
            client.close()
    except BaseException:
        # Exceptions/HTTP bodies may contain credentials and never leave here.
        packet = {'ok': False, 'error': 'metadata_read_failed'}
    finally:
        credential = None
    try:
        encoded = json.dumps(packet, separators=(',', ':')).encode()
        if len(encoded) > _MAX_PACKET:
            encoded = b'{"ok":false,"error":"metadata_packet_invalid"}'
        connection.send_bytes(encoded)
    except BaseException:
        pass
    finally:
        connection.close()


def _read_isolated(credential_provider, deadline):
    """Bound DNS, TLS, body reads and IPC by one deadline; always reap child."""
    limit = min(deadline, monotonic() + 12.)
    if limit <= monotonic():
        return {'ok': False, 'error': 'metadata_deadline',
                'cleanup': {'worker_started': False, 'worker_reaped': True}}
    ctx = multiprocessing.get_context('spawn')
    receive, send = ctx.Pipe(duplex=False)
    worker = ctx.Process(target=_metadata_worker, args=(send, credential_provider, limit), daemon=True)
    packet = {'ok': False, 'error': 'metadata_read_failed'}
    began = monotonic()
    started = False
    forced = False
    try:
        worker.start()
        started = True
        send.close()
        os.set_blocking(receive.fileno(), False)
        buffer = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(receive.fileno(), selectors.EVENT_READ)
            while monotonic() < limit:
                events = selector.select(max(0., limit - monotonic()))
                if not events:
                    break
                chunk = os.read(receive.fileno(), _MAX_PACKET + 5)
                if not chunk:
                    break
                buffer.extend(chunk)
                if len(buffer) >= 4:
                    length = struct.unpack('!i', buffer[:4])[0]
                    if not 0 < length <= _MAX_PACKET:
                        break
                    if len(buffer) >= length + 4:
                        candidate = json.loads(bytes(buffer[4:length + 4]))
                        if isinstance(candidate, dict):
                            packet = candidate
                        break
        if monotonic() >= limit:
            packet = {'ok': False, 'error': 'metadata_deadline'}
    except BaseException:
        packet = {'ok': False, 'error': 'metadata_read_failed'}
    finally:
        send.close()
        receive.close()
        if started:
            worker.join(timeout=min(.15, max(0., limit - monotonic())))
            if worker.is_alive():
                forced = True
                worker.terminate()
                worker.join(timeout=.15)
            if worker.is_alive():
                worker.kill()
                worker.join(timeout=.5)
            reaped = not worker.is_alive()
            cleanup = {'worker_started': True, 'worker_reaped': reaped,
                       'forced_termination': forced, 'exit_code': worker.exitcode,
                       'elapsed_seconds': monotonic() - began, 'maximum_read_seconds': 12}
            if not reaped:
                packet = {'ok': False, 'error': 'metadata_cleanup_failed'}
            elif worker.exitcode != 0:
                packet = {'ok': False, 'error': 'metadata_worker_failed'}
        else:
            cleanup = {'worker_started': False, 'worker_reaped': True,
                       'elapsed_seconds': monotonic() - began}
    packet['cleanup'] = cleanup
    return packet


class BankKeySpendVerifier:
    def __init__(self, credential_provider, evidence_path,
                 input_nano_usd_per_token=150, output_nano_usd_per_token=500, *, reader=None):
        if not callable(credential_provider) or (reader is not None and not callable(reader)):
            raise ContractError(ERROR, 'Explicit credential provider and optional reader required')
        if any(type(v) is not int or v < 0 for v in
               (input_nano_usd_per_token, output_nano_usd_per_token)):
            raise ContractError(ERROR, 'Invalid billing unit prices')
        self.credential_provider = credential_provider
        self.path = Path(evidence_path)
        self.input_price = input_nano_usd_per_token
        self.output_price = output_nano_usd_per_token
        self.reader = reader
        self.baseline = None
        self.stopped = False
        self.call_ids = set()

    def _save(self, evidence):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
        fd = os.open(self.path, flags, 0o600)
        try:
            raw = (json.dumps(evidence, sort_keys=True, allow_nan=False) + '\n').encode()
            with os.fdopen(fd, 'ab', closefd=False) as handle:
                handle.write(raw)
                handle.flush()
                os.fsync(fd)
        finally:
            os.close(fd)

    def _fail(self, evidence, reason):
        self.stopped = True
        evidence.update(passed=False, reason=reason, stopped=True)
        self._save(evidence)
        error = ContractError(ERROR, 'Key spend could not be reconciled; stop without retry')
        error.billing_check = evidence
        raise error

    def _snapshot(self, deadline, evidence):
        try:
            if type(deadline) not in (int, float) or not math.isfinite(deadline) or monotonic() >= deadline:
                raise ValueError()
            result = (self.reader(deadline) if self.reader is not None else
                      _read_isolated(self.credential_provider, deadline))
            if monotonic() >= deadline:
                self._fail(evidence, 'metadata_deadline')
            if not isinstance(result, dict):
                raise ValueError()
            if self.reader is None:
                evidence['cleanup'] = result['cleanup']
                if result.get('ok') is not True:
                    evidence['http_status'] = result.get('http_status')
                    self._fail(evidence, result.get('error', 'metadata_read_failed'))
                snapshot = result['snapshot']
            else:
                # Fake readers cannot smuggle arbitrary response fields into logs.
                evidence['cleanup'] = {'injected_reader': True, 'worker_started': False}
                status = result.get('http_status', result.get('status', 200))
                if type(status) is int and status != 200:
                    evidence['http_status'] = status
                snapshot = _safe_snapshot(result)
            return snapshot
        except ContractError as error:
            if hasattr(error, 'billing_check'):
                raise
            self._fail(evidence, 'metadata_read_failed')
        except BaseException:
            self._fail(evidence, 'metadata_read_failed')

    def start(self, deadline_monotonic):
        evidence = {'schema_version': 'bank-key-spend-check-v1', 'kind': 'baseline',
                    'observed_utc': _now(), 'endpoint': ENDPOINT, 'fake_reader': self.reader is not None}
        if self.stopped or self.baseline is not None:
            self._fail(evidence, 'baseline_already_used_or_stopped')
        snapshot = self._snapshot(deadline_monotonic, evidence)
        evidence['snapshot'] = snapshot
        if Decimal(snapshot['remaining_nano']) < 500_000_000:
            self._fail(evidence, 'insufficient_key_headroom')
        evidence.update(passed=True, minimum_headroom_nano=500_000_000)
        self._save(evidence)
        self.baseline = snapshot
        return evidence

    def __call__(self, call_id, normalized_usage, deadline_monotonic):
        evidence = {'schema_version': 'bank-key-spend-check-v1', 'kind': 'generation_delta',
                    'call_id': call_id, 'observed_utc': _now(), 'fake_reader': self.reader is not None}
        if self.stopped or self.baseline is None or not isinstance(call_id, str) or not call_id or call_id in self.call_ids:
            self._fail(evidence, 'unstarted_duplicate_or_stopped')
        if not isinstance(normalized_usage, dict) or any(type(normalized_usage.get(k)) is not int
                or normalized_usage[k] < 0 for k in ('prompt_tokens', 'completion_tokens')):
            self._fail(evidence, 'missing_or_invalid_usage')
        expected = (normalized_usage['prompt_tokens'] * self.input_price
                    + normalized_usage['completion_tokens'] * self.output_price)
        if expected <= 0:
            self._fail(evidence, 'zero_expected_charge')
        snapshot = self._snapshot(deadline_monotonic, evidence)
        delta = Decimal(snapshot['spend_nano']) - Decimal(self.baseline['spend_nano'])
        evidence.update(before=self.baseline, after=snapshot, delta_nano=str(delta),
                        expected_nano=expected, tolerance_nano=1,
                        usage={k: normalized_usage[k] for k in ('prompt_tokens', 'completion_tokens')})
        if delta <= 0 or abs(delta - Decimal(expected)) > 1:
            self._fail(evidence, 'zero_delayed_or_mismatched_spend')
        if Decimal(snapshot['max_budget_nano']) != Decimal(self.baseline['max_budget_nano']) or (
                snapshot['budget_reset_at'] != self.baseline['budget_reset_at']):
            self._fail(evidence, 'budget_or_reset_changed')
        if Decimal(snapshot['remaining_nano']) < 0:
            self._fail(evidence, 'key_budget_exhausted')
        evidence.update(passed=True, interpretation='One observed receipt reconciled; future charges remain subject to checks')
        self._save(evidence)
        self.baseline = snapshot
        self.call_ids.add(call_id)
        return evidence


class AsyncBankKeySpendVerifier(BankKeySpendVerifier):
    """Price each receipt immediately; allow only attributable delayed postings.

    This is an explicitly authorized risk policy, not a claim that key/info is
    an invoice or that no additional tariff exists. A posting must match a
    prefix of saved receipts. Unexplained amounts, resets and missing usage
    still stop the run. Final posting wait is outside workflow timing.
    """
    def __init__(self, *args, expected_start_spend_nano, **kwargs):
        super().__init__(*args, **kwargs)
        self.expected_start = Decimal(str(expected_start_spend_nano))
        self.cumulative_cost = 0
        self.receipt_prefixes = [0]
        self.observed_delta = Decimal(0)
        self.last_reconciled = None

    def start(self, deadline_monotonic):
        evidence = super().start(deadline_monotonic)
        if abs(Decimal(self.baseline['spend_nano']) - self.expected_start) > 1:
            self._fail(dict(schema_version='bank-async-billing-v1', kind='baseline_inheritance',
                snapshot=self.baseline, expected_start_nano=str(self.expected_start)),
                'unexplained_starting_spend')
        return evidence

    def _observe(self, deadline, evidence):
        snapshot = self._snapshot(deadline, evidence)
        delta = Decimal(snapshot['spend_nano']) - Decimal(self.baseline['spend_nano'])
        evidence.update(baseline=self.baseline, after=snapshot,
            cumulative_expected_nano=self.cumulative_cost, observed_delta_nano=str(delta),
            tolerance_nano=1, all_billable_components_confirmed=False,
            provider_invoice_verified=False)
        if Decimal(snapshot['max_budget_nano']) != Decimal(self.baseline['max_budget_nano']) or (
                snapshot['budget_reset_at'] != self.baseline['budget_reset_at']):
            self._fail(evidence, 'budget_or_reset_changed')
        if delta < -1 or delta + 1 < self.observed_delta:
            self._fail(evidence, 'spend_decreased')
        if not any(abs(delta - prefix) <= 1 for prefix in self.receipt_prefixes):
            self._fail(evidence, 'unexplained_cumulative_spend')
        if Decimal(snapshot['remaining_nano']) < 0:
            self._fail(evidence, 'key_budget_exhausted')
        self.observed_delta = delta
        complete = abs(delta - self.cumulative_cost) <= 1
        evidence.update(passed=True, reconciled=complete,
            status='usage_and_key_delta_reconciled' if complete else 'usage_priced_posting_pending',
            pending_nano=max(0, self.cumulative_cost - int(delta)),
            interpretation='Receipt prices are known; key spend may lag. No claim about future fees.')
        self._save(evidence)
        self.last_reconciled = evidence
        return evidence

    def __call__(self, call_id, normalized_usage, deadline_monotonic):
        evidence = dict(schema_version='bank-async-billing-v1', kind='generation_receipt',
            call_id=call_id, observed_utc=_now(), fake_reader=self.reader is not None)
        if self.stopped or self.baseline is None or not isinstance(call_id, str) or not call_id or call_id in self.call_ids:
            self._fail(evidence, 'unstarted_duplicate_or_stopped')
        usage = normalized_usage
        if not isinstance(usage, dict) or any(type(usage.get(k)) is not int or usage[k] < 0
                for k in ('prompt_tokens', 'completion_tokens')):
            self._fail(evidence, 'missing_or_invalid_usage')
        if usage['prompt_tokens'] > 500000 or usage['completion_tokens'] > 500000:
            self._fail(evidence, 'usage_exceeds_catalog')
        if 'total_tokens' in usage and usage['total_tokens'] != usage['prompt_tokens'] + usage['completion_tokens']:
            self._fail(evidence, 'inconsistent_usage_total')
        reasoning = usage.get('reasoning_tokens', 0)
        if type(reasoning) is not int or not 0 <= reasoning <= usage['completion_tokens']:
            self._fail(evidence, 'inconsistent_reasoning_usage')
        expected = usage['prompt_tokens'] * self.input_price + usage['completion_tokens'] * self.output_price
        if expected <= 0:
            self._fail(evidence, 'zero_expected_charge')
        self.cumulative_cost += expected
        self.receipt_prefixes.append(self.cumulative_cost)
        self.call_ids.add(call_id)
        evidence.update(expected_nano=expected, usage={k: usage[k] for k in
            ('prompt_tokens', 'completion_tokens')}, reasoning_in_completion=True)
        return self._observe(deadline_monotonic, evidence)

    def finalize(self, deadline_monotonic, *, poll_seconds=10., sleep=None):
        """Only read metadata while waiting; never dispatch or retry generation."""
        from time import sleep as real_sleep
        sleep = real_sleep if sleep is None else sleep
        began = monotonic()
        if self.stopped:
            return dict(passed=False, reconciled=False, status='billing_hard_stopped',
                        wait_seconds=0, generation_requests=0)
        while True:
            evidence = dict(schema_version='bank-async-billing-v1', kind='final_account_check',
                observed_utc=_now(), generation_requests=0, wait_seconds=monotonic()-began)
            remaining = deadline_monotonic-monotonic()
            if remaining <= 0:
                evidence.update(passed=False, reconciled=False, status='posting_wait_expired',
                    expected_nano=self.cumulative_cost, observed_delta_nano=str(self.observed_delta))
                self._save(evidence)
                return evidence
            result = self._observe(min(deadline_monotonic, monotonic()+12), evidence)
            if result['reconciled']:
                result['wait_seconds'] = monotonic()-began
                return result
            sleep(min(poll_seconds, max(0., deadline_monotonic-monotonic())))


class UnorderedBankKeySpendVerifier(AsyncBankKeySpendVerifier):
    """Accept delayed, unordered postings only when saved receipts explain them.

    Keep every compatible subset because equal prices need not identify a
    particular call. Successive observations must admit an expanding subset;
    a charge cannot disappear and then be attributed to a different receipt.
    This is aggregate reconciliation, never a per-call provider invoice.
    The older prefix-only policy remains unchanged for archived experiments.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.receipts = []
        self.subset_costs = [0]
        self.compatible_subsets = {0}

    def _observe(self, deadline, evidence):
        if evidence.get('kind') == 'generation_receipt':
            if len(self.receipts) >= 20:
                self._fail(evidence, 'receipt_set_limit')
            self.receipts.append((evidence['call_id'], evidence['expected_nano']))
            self.subset_costs += [value + evidence['expected_nano']
                                 for value in self.subset_costs]
        snapshot = self._snapshot(deadline, evidence)
        delta = Decimal(snapshot['spend_nano']) - Decimal(self.baseline['spend_nano'])
        evidence.update(schema_version='bank-unordered-billing-v1', baseline=self.baseline,
            after=snapshot, cumulative_expected_nano=self.cumulative_cost,
            observed_delta_nano=str(delta), tolerance_nano=1,
            all_billable_components_confirmed=False, provider_invoice_verified=False,
            policy='known-receipts-expanding-subset', receipt_count=len(self.receipts))
        if Decimal(snapshot['max_budget_nano']) != Decimal(self.baseline['max_budget_nano']) or (
                snapshot['budget_reset_at'] != self.baseline['budget_reset_at']):
            self._fail(evidence, 'budget_or_reset_changed')
        if delta < -1 or delta + 1 < self.observed_delta:
            self._fail(evidence, 'spend_decreased')
        candidates = {mask for mask, cost in enumerate(self.subset_costs)
                      if abs(delta - cost) <= 1 and any(
                          mask & prior == prior for prior in self.compatible_subsets)}
        if not candidates:
            self._fail(evidence, 'unexplained_or_inconsistent_receipt_subset')
        if Decimal(snapshot['remaining_nano']) < 0:
            self._fail(evidence, 'key_budget_exhausted')
        self.compatible_subsets = candidates
        self.observed_delta = delta
        complete = (1 << len(self.receipts)) - 1 in candidates
        evidence.update(passed=True, reconciled=complete,
            status='usage_and_key_delta_reconciled' if complete else 'usage_priced_posting_pending',
            pending_nano=max(0, self.cumulative_cost-int(delta)),
            compatible_subset_count=len(candidates),
            compatible_call_subsets=[[cid for i, (cid, _) in enumerate(self.receipts)
                                      if mask & (1 << i)] for mask in sorted(candidates)[:32]],
            subsets_truncated=len(candidates) > 32,
            interpretation='Aggregate spend matches saved receipt combinations; individual posting order and future fees are not verified.')
        self._save(evidence)
        self.last_reconciled = evidence
        return evidence

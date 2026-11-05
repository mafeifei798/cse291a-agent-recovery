#!/usr/bin/env python3
"""Explicit P4 formal batch entry; no probes and no automatic HTTP retries."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
from time import monotonic, sleep

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from agent_recovery.contracts import ContractError, digest, require, utc_now
from agent_recovery.p4_runner import run_batch, write


def execute(root, *, stop_after, grant=None, fixture=False):
    from agent_recovery.p4_config import make_binding
    binding = make_binding(simulated=fixture)
    root = Path(root).resolve()
    campaign_id = 'p4-formal-fixture-v1' if fixture else 'p4-formal-live-v1'
    factory = counter = None
    if not fixture:
        require(isinstance(grant, dict) and grant.get('authorized') is True
            and grant.get('simulated') is False
            and grant.get('output_root') == str(root)
            and grant.get('campaign_id') == campaign_id
            and grant.get('binding_digest') == binding.binding_digest
            and grant.get('max_new_calls') == 840
            and grant.get('max_total_calls') == 1843
            and grant.get('max_cost_nano_usd') == 1_000_000_000
            and isinstance(grant.get('authorization_reference'), str)
            and bool(grant['authorization_reference'].strip()),
            'Explicit matching formal authorization required', 'P4_REAL_DISABLED')
        from agent_recovery.p3_deadline import BoundedHTTPSender
        from agent_recovery.p3_transport import BoundTokenCounter, LiveRuntimePermit, P3HTTPClient
        counter = BoundTokenCounter(binding.token_admission_evidence, lambda request: 4000)
        permit = LiveRuntimePermit(True, binding.binding_digest, grant['authorization_reference'])
        permit.validate(binding)
        secret, last_start = [], [None]

        def credential_provider():
            if not secret:
                value = os.environ.get('OPENAI_API_KEY')
                require(isinstance(value, str) and 0 < len(value) <= 4096
                    and all(33 <= ord(c) <= 126 for c in value),
                    'Injected course credential unavailable', 'P4_CREDENTIAL_ERROR')
                secret.append(value)
            if last_start[0] is not None:
                remaining = last_start[0] + 1 - monotonic()
                if remaining > 0:
                    sleep(remaining)
            last_start[0] = monotonic()
            return secret[0]

        def factory():
            return P3HTTPClient(binding, BoundedHTTPSender(), token_counter=counter,
                credential_provider=credential_provider, runtime_permit=permit)
    try:
        return run_batch(root, binding, campaign_id=campaign_id, stop_after=stop_after,
            client_factory=factory, token_counter=counter, authorization=grant)
    finally:
        if not fixture:
            secret.clear()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True)
    parser.add_argument('--stop-after', type=int, choices=(14, 56, 112, 168), default=14)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--fixture', action='store_true')
    mode.add_argument('--execute-real', action='store_true')
    parser.add_argument('--grant')
    args = parser.parse_args(argv)
    require(args.fixture or args.grant is not None, 'Real execution needs a grant file', 'P4_REAL_DISABLED')
    grant = json.loads(Path(args.grant).read_text()) if args.grant else None
    result = execute(args.root, stop_after=args.stop_after, grant=grant, fixture=args.fixture)
    print(json.dumps({k: result[k] for k in ('status', 'checkpoint', 'processed_slots', 'executed_slots',
        'not_started_slots', 'real_api_requests', 'budget', 'cumulative')}, sort_keys=True), flush=True)
    return 0 if result['status'] in ('checkpoint', 'completed') else 2


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except ContractError as exc:
        print(json.dumps({'status': 'stopped', 'error_code': exc.code}), flush=True)
        raise SystemExit(2)

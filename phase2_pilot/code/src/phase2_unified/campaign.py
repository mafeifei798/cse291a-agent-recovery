"""Batch entry, immutable receipts and no-retry continuation for fake clients."""
import copy
import sys
from pathlib import Path

from .budget import Ledger, VirtualClock
from phase2_offline.common import digest, read, require, save, sha

ROOT = Path(__file__).resolve().parents[2]
APPROVED_PACK_SHA256 = '3d66f337dde6cd6aebda205584c4c7b8cade8d06f614f105056e496f49b4ef2a'


def source_pins():
    paths = list((ROOT/'src/phase2_offline').glob('*.py')) + list((ROOT/'src/phase2_supplement').glob('*.py')) + list((ROOT/'src/phase2_unified').glob('*.py'))
    for folder in ('sr_recovery_v2', 'sr_recovery_timing', 'sr_cpu_v2'):
        paths.extend((ROOT/'src'/folder).glob('*.py'))
    paths.extend((ROOT/'phase2/p0').glob('*.py'))
    paths.extend(ROOT/'scripts'/name for name in ('run_phase2_unified.py','check_phase2_unified.py','freeze_phase2_unified.py'))
    paths.extend(p for p in (ROOT/'sr_v2/v0/fixtures/n2').rglob('*') if p.is_file()
                 and '__pycache__' not in p.parts)
    return {str(p.relative_to(ROOT)): sha(p) for p in sorted(paths)}


def load_pack(path=None):
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from .pack import load_pack as load
    pack = load(path)
    require(pack['freeze_sha256'] == APPROVED_PACK_SHA256, 'UNAPPROVED_EVALUATION_PACK')
    return pack


def _checkpoint_exports(ledger):
    return {r['row_id']: r['result_sha256'] for r in ledger.state['rows']
            if r['result_sha256'] is not None}


def _save_state(root, ledger, pack):
    snapshot = ledger.snapshot()
    save(root/'ledger.json', snapshot, replace=(root/'ledger.json').exists())
    save(root/'campaign_state.json', dict(mode='offline_fixture', fixture_only=True,
         real_api_calls=0, real_training_jobs=0, pack_digest=pack['freeze_sha256'],
         rows=snapshot['rows'], stopped_reason=snapshot['stopped_reason'], implementation_revision='phase2-unified-r1'),
         replace=(root/'campaign_state.json').exists())


def run_campaign(output, *, pack_path=None, through_batch=1, resume=False, fake_cases=None,
                 limits=None, logical_clock=None):
    """Execute exactly the next registered block, using synthetic IO exclusively.

    No injected transport, credential provider, or live switch is accepted.
    Tests can change limits downward and inject fake failures into new campaigns.
    """
    from .runtime import RuntimeStop, run_row
    from .audit import audit_campaign, audit_row
    from phase2_offline.artifacts import seal_artifacts
    root = Path(output).resolve()
    pack = load_pack(pack_path)
    rows = pack['rows']
    batches = list(dict.fromkeys(r['batch_id'] for r in rows))
    require(type(through_batch) is int and 1 <= through_batch <= len(batches), 'INVALID_BATCH')
    require(not Path(output).is_symlink(), 'OUTPUT_SYMLINK')
    # Never initialize over any existing directory, including an old experiment.
    existing = root.exists()
    require(existing == resume, 'EXPLICIT_FRESH_OR_RESUME_REQUIRED')
    config = dict(mode='offline_fixture', fixture_only=True, pack_digest=pack['freeze_sha256'],
                  source_pins=source_pins(), fake_cases=fake_cases or {}, limits=limits)
    if existing:
        require(read(root/'frozen_config.json') == config, 'FROZEN_CONFIGURATION_CHANGED')
        require(read(root/'registry.json') == rows, 'SAVED_REGISTRY_CHANGED')
    else:
        root.mkdir(parents=True)
        save(root/'frozen_config.json', config)
        save(root/'registry.json', rows)
    ledger = Ledger(root/'budget/ledger.sqlite', rows, pack['freeze_sha256'], limits=limits)
    clock = logical_clock or VirtualClock(ledger.state['last_response_ns'] or 0)
    try:
        ledger.assert_resumable()
        for previous in ledger.state['checkpoints']:
            receipt = read(root/'checkpoints'/f"{previous['batch_id']}.json")
            require(receipt == previous, 'CHECKPOINT_MISMATCH')
            audit = read(root/'audits'/f"{previous['batch_id']}.json")
            require(digest(audit) == previous['audit_digest'] and audit['passed'], 'PREVIOUS_AUDIT_MISMATCH')
        for recorded in ledger.state['rows']:
            if recorded['result_sha256']:
                item_path = root/'rows'/recorded['row_id']/'item.json'
                require(sha(item_path) == recorded['result_sha256'], 'PRIOR_ROW_CHANGED')
        if existing:
            previous_audit = audit_campaign(root, pack=pack, require_complete=False)
            require(previous_audit['passed'], 'PRIOR_EVIDENCE_AUDIT_FAILED')
        completed_batches = len(ledger.state['checkpoints'])
        require(through_batch <= completed_batches+1, 'PREVIOUS_BATCH_ACCEPTANCE_REQUIRED')
        if through_batch <= completed_batches:
            return dict(passed=True, idempotent_noop=True, real_api_calls=0,
                        completed_batches=completed_batches, ledger=ledger.snapshot())

        def hook(event):
            event = copy.deepcopy(event)
            try:
                if event['stage'] == 'before':
                    ledger.reserve(event, clock)
                elif event['stage'] == 'after':
                    case = (fake_cases or {}).get(event['row_id'])
                    own = [c for c in ledger.state['calls'] if c['row_id'] == event['row_id']]
                    if case in ('http_429', 'unknown_usage', 'malformed_usage') and len(own) == 1:
                        if case == 'malformed_usage':
                            event['usage'] = {'prompt_tokens': -1, 'completion_tokens': 1, 'total_tokens': 0}
                        else:
                            event.update(status='uncertain', usage=None, http_status=429 if case == 'http_429' else 200)
                    ledger.settle(event, clock)
                    if ledger.state['stopped_reason']:
                        stopped = RuntimeStop(ledger.state['stopped_reason'], unknown_usage=True)
                        stopped.transport_event = event
                        raise stopped
                else:
                    raise ValueError('UNKNOWN_DISPATCH_STAGE')
                return event
            except RuntimeStop:
                raise
            except Exception as exc:
                ledger.stop(getattr(exc, 'code', str(exc)))
                raise RuntimeStop(getattr(exc, 'code', str(exc))) from exc

        current_batch = batches[through_batch-1]
        for row in [r for r in rows if r['batch_id'] == current_batch]:
            tracked = ledger.row(row['row_id'])
            if tracked['status'] != 'not_started':
                continue
            row_dir = root/'rows'/row['row_id']
            prefix = None
            if row['kind'] in ('recovery', 'consumption_recovery'):
                prefix = root/'rows'/row['prefix_row_id']
                prior = read(prefix/'item.json')
                if prior.get('qualified') is not True:
                    row_dir.mkdir(parents=True)
                    save(row_dir/'item.json', dict(row_id=row['row_id'], mode='offline_fixture',
                        fixture_only=True, status='not_run_blocked_prefix',
                        terminal_status='not_run_blocked_prefix', qualified=False,
                        prefix_row_id=row['prefix_row_id'], real_api_calls=0,
                        reason='Natural prefix failure; no replacement scene or recovery attempt.'))
                    ledger.block_row(row['row_id'], sha(row_dir/'item.json'))
                    _save_state(root, ledger, pack)
                    continue
            ledger.start_row(row['row_id'])
            _save_state(root, ledger, pack)
            try:
                case = (fake_cases or {}).get(row['row_id'])
                runtime_case = None if case in ('http_429', 'unknown_usage', 'malformed_usage') else case
                result = run_row(pack, row, row_dir, scene=prefix, dispatch_hook=hook, fake_case=runtime_case)
                exported = read(row_dir/'export.json')
                seal_artifacts(row_dir, exported)
                independent = audit_row(row, row_dir, pack=pack)
                save(row_dir/'independent_audit.json', independent)
                status = result.get('terminal_status') or result['status']
                ledger.finish_row(row['row_id'], status, sha(row_dir/'item.json'))
                if not independent['passed']:
                    ledger.stop('INDEPENDENT_ROW_AUDIT_FAILED')
            except Exception as exc:
                save(row_dir/'campaign_failure.json', dict(code=getattr(exc,'code',type(exc).__name__), message=str(exc)))
                ledger.stop('ROW_INFRASTRUCTURE_ERROR:' + getattr(exc, 'code', type(exc).__name__))
                if tracked['status'] == 'running':
                    # Do not invent a successful closure after an interrupted controller.
                    ledger.finish_row(row['row_id'], 'uncertain', sha(row_dir/'item.json') if (row_dir/'item.json').exists() else None)
            _save_state(root, ledger, pack)
            if ledger.state['stopped_reason']:
                break
        result = audit_campaign(root, pack=pack, require_complete=through_batch==3 and not ledger.state['stopped_reason'])
        save(root/'audits'/f'{current_batch}.json', result)
        if not result['passed']:
            ledger.stop('INDEPENDENT_CAMPAIGN_AUDIT_FAILED')
        if ledger.state['stopped_reason'] is None:
            checkpoint = ledger.checkpoint(current_batch, digest(result), digest(_checkpoint_exports(ledger)))
            save(root/'checkpoints'/f'{current_batch}.json', checkpoint)
        _save_state(root, ledger, pack)
        return dict(passed=result['passed'] and ledger.state['stopped_reason'] is None,
                    audit=result, completed_batches=len(ledger.state['checkpoints']),
                    real_api_calls=0, real_training_jobs=0, ledger=ledger.snapshot())
    finally:
        ledger.close()

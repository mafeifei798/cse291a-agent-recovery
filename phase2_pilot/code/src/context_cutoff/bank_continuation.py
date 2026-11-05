"""Continue the one reconciled Bank prefix without rewriting its failed run."""
from copy import deepcopy
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sqlite3
from urllib.parse import quote
import zipfile

from agent_recovery.contracts import canonical_json, digest, require
from .bank_pilot_budget import BankPilotBudget
from .bank_gateway import BankPilotGateway
from .triton import validate_payload

PRIOR_ARCHIVE_SHA = 'f7e9847992b9aed891df65350f5d43cd3354326504a8db9d4d88711b69e2fb58'
R2_ARCHIVE_SHA = 'ebd59a32dc1b68909dae23ff897152ece5199db2bb3b4f3b66330ccde4374a15'
R2_POSTSTOP_SHA = 'e4a67e669e3fc301da83787fbca73b6b7fb88a1c78dd76e0d82806df24eec2fa'
R3_ARCHIVE_SHA = '0c8437cd447a780a766b0d8dc490d1daf53d0a15a8ce5052a7bd254c53a12d0b'
R3_POSTSTOP_SHA = 'bbca4b31075adf5b358563065fa8cd22e3c151453460878b48921f153ba8784b'
R4_ARCHIVE_SHA = '7608018545587c6d89cb17e6c847215b1b92976fb137f143825d8f8c48b1937c'
R4_POSTSTOP_SHA = '315989f036453bd3047056ad7528ea6a94c055f9edd8c815030963b0c2ee6050'
R5_ARCHIVE_SHA = '7a8e159ed7722256f19bee596dd2935b6c2a0914f1179bc5c53e041c75b537b4'
R5_POSTSTOP_SHA = '5f6487841a47ad2a316afcb25029f6d9a3b7d0e88a4850ac4ad920fab074f2e9'


def load_continuation(archive, poststop):
    archive, poststop = Path(archive), Path(poststop)
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == PRIOR_ARCHIVE_SHA,
            'Original failed archive differs', 'BANK_CONTINUATION_SOURCE')
    prefix = 'outputs/bank_c01c02_real_r1/'
    with zipfile.ZipFile(archive) as z:
        manifest = json.loads(z.read(prefix+'EVIDENCE_MANIFEST.json'))['files']
        for name, pin in manifest.items():
            require(hashlib.sha256(z.read(name)).hexdigest() == pin,
                    'Original evidence hash differs', 'BANK_CONTINUATION_SOURCE')
        ledger = json.loads(z.read(prefix+'LEDGER.json'))
        checks = [json.loads(line) for line in z.read(prefix+'KEY_SPEND.jsonl').decode().splitlines()]
    require(ledger['status'] == 'quarantined' and len(ledger['calls']) == 1,
            'Expected one original stopped call', 'BANK_CONTINUATION_SOURCE')
    call = ledger['calls'][0]
    require(call['call_id'] == 'C01.initial.llm.0000' and call['dispatched']
            and call['step_id'] == 'Analyst', 'Original call identity differs', 'BANK_CONTINUATION_SOURCE')
    evidence = call['evidence']; audit = evidence['wire_audit']; usage = evidence['observed_usage']
    require(audit['status'] == 200 and audit['cleanup_receipt']['reaped']
            and not audit['cleanup_receipt']['cleanup_failed'],
            'Original response or cleanup incomplete', 'BANK_CONTINUATION_SOURCE')
    payload = validate_payload('Analyst', json.loads(audit['raw_response']['choices'][0]['message']['content']))
    cost = usage['prompt_tokens']*150 + usage['completion_tokens']*500
    post = json.loads(poststop.read_text())
    before = Decimal(checks[0]['snapshot']['spend_nano'])
    after = Decimal(str(post['spend_usd']))*10**9
    require(cost == 65400 and post['http_status'] == 200 and abs(after-before-cost) <= 1,
            'Prior fee has not been independently reconciled', 'BANK_CONTINUATION_SOURCE')
    result = dict(schema_version='bank-reconciled-prefix-v1', archive_sha256=PRIOR_ARCHIVE_SHA,
        poststop_sha256=hashlib.sha256(poststop.read_bytes()).hexdigest(),
        inherited_generation_calls=1, inherited_known_nano=cost,
        expected_start_key_spend_nano=str(after), call_id=call['call_id'], run_id='C01',
        role='Analyst', request=call['request'], sidecar=call['sidecar'],
        payload=payload, usage=usage, wire_audit=audit,
        original_state_preserved=True, original_hold_replaced_only_in_derived_accounting=True)
    result['continuation_sha256'] = digest(result)
    return result


def load_protocol_continuation(archive, poststop, r2_archive, r2_poststop):
    """Carry both paid calls; never turn the rejected second output into success."""
    result=load_continuation(archive,poststop)
    for path,pin in ((r2_archive,R2_ARCHIVE_SHA),(r2_poststop,R2_POSTSTOP_SHA)):
        require(hashlib.sha256(Path(path).read_bytes()).hexdigest()==pin,
                'Prior r2 evidence differs','BANK_CONTINUATION_SOURCE')
    prefix='outputs/bank_c01c02_real_r2/'
    with zipfile.ZipFile(r2_archive) as z:
        manifest=json.loads(z.read(prefix+'EVIDENCE_MANIFEST.json'))['files']
        for name,pin in manifest.items():
            require(hashlib.sha256(z.read(name)).hexdigest()==pin,
                    'Prior r2 file differs','BANK_CONTINUATION_SOURCE')
        ledger=json.loads(z.read(prefix+'LEDGER.json'))
    require(ledger['status']=='quarantined' and len(ledger['calls'])==1,
            'Expected one rejected second call','BANK_CONTINUATION_SOURCE')
    row=ledger['calls'][0];evidence=row['evidence'];audit=evidence['wire_audit']
    usage=evidence['observed_usage']
    require(row['call_id']=='C01.initial.llm.0001' and row['dispatched']
            and evidence['error']=='CTX_MODEL_SCHEMA' and audit['status']==200
            and audit['cleanup_receipt']['reaped'] and not audit['cleanup_receipt']['cleanup_failed'],
            'Unexpected second call identity or outcome','BANK_CONTINUATION_SOURCE')
    cost=usage['prompt_tokens']*150+usage['completion_tokens']*500
    require(usage['total_tokens']==usage['prompt_tokens']+usage['completion_tokens'] and cost==130900,
            'Second receipt usage differs','BANK_CONTINUATION_SOURCE')
    with zipfile.ZipFile(r2_poststop) as z:
        manifest=json.loads(z.read('POSTSTOP_MANIFEST.json'))['files']
        for name,pin in manifest.items():
            require(hashlib.sha256(z.read(name)).hexdigest()==pin,
                    'Prior poststop file differs','BANK_CONTINUATION_SOURCE')
        post=json.loads(z.read('POSTSTOP_KEY_SPEND.json'))
    after=Decimal(post['snapshot']['spend_nano'])
    require(post['reconciled'] and post['generation_requests']==0
            and post['run_resumed'] is False
            and abs(after-Decimal(result['expected_start_key_spend_nano'])-cost)<=1,
            'Second call fee not reconciled','BANK_CONTINUATION_SOURCE')
    result.update(schema_version='bank-reconciled-prefix-v2',
        r2_archive_sha256=R2_ARCHIVE_SHA,r2_poststop_sha256=R2_POSTSTOP_SHA,
        inherited_generation_calls=2,inherited_known_nano=65400+cost,
        expected_start_key_spend_nano=str(after),
        rejected_prior_call_ids=[row['call_id']],
        rejected_prior_call_preserved=True,rejected_prior_output_reused=False,
        analyst_protocol_revision='bank-analyst-output-r3')
    result['continuation_sha256']=digest({k:v for k,v in result.items() if k!='continuation_sha256'})
    return result


def load_contract_continuation(archive,poststop,r2_archive,r2_poststop,r3_archive,r3_poststop):
    """Preserve the Analyst repair and continue the clarified Planner contract."""
    result=load_protocol_continuation(archive,poststop,r2_archive,r2_poststop)
    require(hashlib.sha256(Path(r3_archive).read_bytes()).hexdigest()==R3_ARCHIVE_SHA
            and hashlib.sha256(Path(r3_poststop).read_bytes()).hexdigest()==R3_POSTSTOP_SHA,
            'Prior r3 archive differs','BANK_CONTINUATION_SOURCE')
    prefix='outputs/bank_c01c02_real_r3/'
    with zipfile.ZipFile(r3_archive) as z:
        manifest=json.loads(z.read(prefix+'EVIDENCE_MANIFEST.json'))['files']
        for name,pin in manifest.items():
            require(hashlib.sha256(z.read(name)).hexdigest()==pin,'Prior r3 file differs','BANK_CONTINUATION_SOURCE')
        ledger=json.loads(z.read(prefix+'LEDGER.json'))
    rows=ledger['calls']
    require(len(rows)==2 and rows[0]['call_id']=='C01.initial.llm.0002'
            and rows[0]['step_id']=='Analyst' and rows[0]['status']=='settled'
            and rows[1]['call_id']=='C01.initial.llm.0003' and rows[1]['step_id']=='Planner'
            and rows[1]['evidence']['error']=='CTX_MODEL_SCHEMA',
            'Unexpected r3 saved prefix','BANK_CONTINUATION_SOURCE')
    prior=[dict(call_id='C01.initial.llm.0000',run_id='C01',step_id='Analyst',cost_nano=65400),
           dict(call_id='C01.initial.llm.0001',run_id='C01',step_id='Analyst',cost_nano=130900)]
    for row in rows:
        audit=row['evidence']['wire_audit'];usage=row.get('usage') or row['evidence']['observed_usage']
        require(audit['status']==200 and audit['cleanup_receipt']['reaped']
                and not audit['cleanup_receipt']['cleanup_failed']
                and usage['total_tokens']==usage['prompt_tokens']+usage['completion_tokens'],
                'Incomplete r3 receipt','BANK_CONTINUATION_SOURCE')
        prior.append(dict(call_id=row['call_id'],run_id='C01',step_id=row['step_id'],
            cost_nano=usage['prompt_tokens']*150+usage['completion_tokens']*500))
    with zipfile.ZipFile(r3_poststop) as z:
        manifest=json.loads(z.read('POSTSTOP_MANIFEST.json'))['files']
        for name,pin in manifest.items():
            require(hashlib.sha256(z.read(name)).hexdigest()==pin,'r3 poststop differs','BANK_CONTINUATION_SOURCE')
        post=json.loads(z.read('POSTSTOP_KEY_SPEND.json'))
    after=Decimal(post['snapshot']['spend_nano']);new_cost=sum(x['cost_nano'] for x in prior[2:])
    require(post['generation_requests']==0 and post['run_resumed'] is False and post['reconciled']
            and abs(after-Decimal(result['expected_start_key_spend_nano'])-new_cost)<=1
            and new_cost==388000,'r3 fees differ','BANK_CONTINUATION_SOURCE')
    accepted=rows[0];evidence=accepted['evidence']
    payload=validate_payload('Analyst',evidence['payload'])
    replay=dict(call_id=accepted['call_id'],run_id='C01',role='Analyst',request=accepted['request'],
        sidecar=accepted['sidecar'],payload=payload,usage=accepted['usage'],wire_audit=evidence['wire_audit'])
    result.update(schema_version='bank-reconciled-prefix-v3',r3_archive_sha256=R3_ARCHIVE_SHA,
        r3_poststop_sha256=hashlib.sha256(Path(r3_poststop).read_bytes()).hexdigest(),
        inherited_generation_calls=4,inherited_known_nano=sum(x['cost_nano'] for x in prior),
        expected_start_key_spend_nano=str(after),inherited_paid_receipts=prior,
        additional_replay_prefix=[replay],rejected_prior_call_ids=['C01.initial.llm.0001','C01.initial.llm.0003'],
        analyst_protocol_revision='bank-agent-contract-r4')
    result['continuation_sha256']=digest({k:v for k,v in result.items() if k!='continuation_sha256'})
    return result


def load_envelope_continuation(archive,poststop,r2_archive,r2_poststop,r3_archive,r3_poststop,r4_archive,r4_poststop):
    from .bank_output_protocol import decode_output
    result=load_contract_continuation(archive,poststop,r2_archive,r2_poststop,r3_archive,r3_poststop)
    require(hashlib.sha256(Path(r4_archive).read_bytes()).hexdigest()==R4_ARCHIVE_SHA
            and hashlib.sha256(Path(r4_poststop).read_bytes()).hexdigest()==R4_POSTSTOP_SHA,
            'r4 source archive differs','BANK_CONTINUATION_SOURCE')
    prefix='outputs/bank_c01c02_real_r4/'
    with zipfile.ZipFile(r4_archive) as z:
        manifest=json.loads(z.read(prefix+'EVIDENCE_MANIFEST.json'))['files']
        for name,pin in manifest.items():
            require(hashlib.sha256(z.read(name)).hexdigest()==pin,'r4 source file differs','BANK_CONTINUATION_SOURCE')
        rows=json.loads(z.read(prefix+'LEDGER.json'))['calls']
    require([(x['call_id'],x['step_id']) for x in rows]==[
        ('C01.initial.llm.0004','Planner'),('C01.initial.llm.0005','Executor'),('C01.initial.llm.0006','Executor')]
        and rows[-1]['evidence']['error']=='CTX_MODEL_SCHEMA',
        'Unexpected saved r4 prefix','BANK_CONTINUATION_SOURCE')
    prior=deepcopy(result['inherited_paid_receipts']);replay=deepcopy(result['additional_replay_prefix'])
    for row in rows:
        evidence=row['evidence'];audit=deepcopy(evidence['wire_audit'])
        usage=row.get('usage') or evidence['observed_usage']
        require(audit['status']==200 and audit['cleanup_receipt']['reaped']
                and not audit['cleanup_receipt']['cleanup_failed']
                and usage['total_tokens']==usage['prompt_tokens']+usage['completion_tokens'],
                'r4 incomplete receipt','BANK_CONTINUATION_SOURCE')
        prior.append(dict(call_id=row['call_id'],run_id='C01',step_id=row['step_id'],
            cost_nano=usage['prompt_tokens']*150+usage['completion_tokens']*500))
        raw=json.loads(audit['raw_response']['choices'][0]['message']['content'])
        payload,normalization=decode_output(row['step_id'],raw)
        audit['output_protocol_reacceptance']=normalization
        audit['original_failure_preserved']=bool(evidence.get('error'))
        replay.append(dict(call_id=row['call_id'],run_id='C01',role=row['step_id'],
            request=row['request'],sidecar=row['sidecar'],payload=payload,usage=usage,wire_audit=audit))
    require(replay[-1]['payload']=={'tool':'train','arguments':{}},
            'Only the already received exact train request can be adopted','BANK_CONTINUATION_SOURCE')
    with zipfile.ZipFile(r4_poststop) as z:
        for name,pin in json.loads(z.read('POSTSTOP_MANIFEST.json'))['files'].items():
            require(hashlib.sha256(z.read(name)).hexdigest()==pin,'r4 poststop differs','BANK_CONTINUATION_SOURCE')
        post=json.loads(z.read('POSTSTOP_KEY_SPEND.json'))
    after=Decimal(post['snapshot']['spend_nano']);cost=sum(x['cost_nano'] for x in prior[4:])
    require(cost==545250 and post['generation_requests']==0 and post['run_resumed'] is False
            and post['reconciled'] and abs(after-Decimal(result['expected_start_key_spend_nano'])-cost)<=1,
            'r4 spend not reconciled','BANK_CONTINUATION_SOURCE')
    result.update(schema_version='bank-reconciled-prefix-v4',r4_archive_sha256=R4_ARCHIVE_SHA,
        r4_poststop_sha256=hashlib.sha256(Path(r4_poststop).read_bytes()).hexdigest(),
        inherited_generation_calls=7,inherited_known_nano=sum(x['cost_nano'] for x in prior),
        expected_start_key_spend_nano=str(after),inherited_paid_receipts=prior,
        additional_replay_prefix=replay,reinterpreted_prior_call_ids=['C01.initial.llm.0006'],
        prior_failed_runs_reclassified=False,analyst_protocol_revision='bank-agent-output-r5')
    result['continuation_sha256']=digest({k:v for k,v in result.items() if k!='continuation_sha256'})
    return result


def load_c02_continuation(archive, poststop, r2_archive, r2_poststop, r3_archive,
                          r3_poststop, r4_archive, r4_poststop, r5_archive, r5_poststop):
    """Carry all eleven paid receipts; preserve completed C01 and replay C02.0.

    Read and hash the archived C01 result, never load its model or execute it.
    The old uncertain ledger and its reserve remain untouched in that archive.
    Only this new, derived authority replaces the resolved reserve with cost.
    """
    from .bank_output_protocol import decode_output
    result = load_envelope_continuation(archive, poststop, r2_archive, r2_poststop,
                                       r3_archive, r3_poststop, r4_archive, r4_poststop)
    prefix = 'outputs/bank_c01c02_real_r5/'
    for path, pin in ((r5_archive, R5_ARCHIVE_SHA), (r5_poststop, R5_POSTSTOP_SHA)):
        require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == pin,
                'r5 archive differs', 'BANK_CONTINUATION_SOURCE')
    with zipfile.ZipFile(r5_archive) as z:
        for name, pin in json.loads(z.read(prefix+'EVIDENCE_MANIFEST.json'))['files'].items():
            require(hashlib.sha256(z.read(name)).hexdigest() == pin,
                    'r5 saved file differs', 'BANK_CONTINUATION_SOURCE')
        ledger = json.loads(z.read(prefix+'LEDGER.json'))
        summary = json.loads(z.read(prefix+'RESULTS.json'))
        c01 = json.loads(z.read(prefix+'runs/C01/trace.json'))
        numeric = json.loads(z.read(prefix+'runs/C01/NUMERIC_EXECUTION.json'))
    require(summary['actual_training'] == summary['actual_prediction'] == 1
            and summary['runs'][0]['run_id'] == 'C01'
            and summary['runs'][0]['outcome'] == 'correct_complete'
            and c01['final']['outcome'] == 'correct_complete'
            and numeric['response']['passed'] is True
            and numeric['response']['business_correct'] is True
            and numeric['execution']['worker_reaped'] is True,
            'C01 completion and independent check required', 'BANK_CONTINUATION_SOURCE')
    rows = ledger['calls']
    require([(r['call_id'], r['run_id'], r['step_id']) for r in rows] == [
        ('C01.initial.llm.0007', 'C01', 'Executor'),
        ('C01.initial.llm.0008', 'C01', 'Executor'),
        ('C01.initial.llm.0009', 'C01', 'Executor'),
        ('C02.initial.llm.0000', 'C02', 'Analyst')]
        and all(r['status'] == 'settled' for r in rows[:3])
        and rows[-1]['evidence']['error'] == 'BANK_BILLING_UNRECONCILED',
        'Unexpected r5 receipt sequence', 'BANK_CONTINUATION_SOURCE')
    prior = deepcopy(result['inherited_paid_receipts'])
    for row in rows:
        evidence = row['evidence']; audit = evidence['wire_audit']
        usage = row.get('usage') or evidence['observed_usage']
        require(audit['status'] == 200 and audit['cleanup_receipt']['reaped']
                and not audit['cleanup_receipt']['cleanup_failed']
                and usage['total_tokens'] == usage['prompt_tokens']+usage['completion_tokens'],
                'Incomplete r5 receipt', 'BANK_CONTINUATION_SOURCE')
        prior.append(dict(call_id=row['call_id'], run_id=row['run_id'], step_id=row['step_id'],
                          cost_nano=usage['prompt_tokens']*150+usage['completion_tokens']*500))
    with zipfile.ZipFile(r5_poststop) as z:
        for name, pin in json.loads(z.read('POSTSTOP_MANIFEST.json'))['files'].items():
            require(hashlib.sha256(z.read(name)).hexdigest() == pin,
                    'r5 poststop differs', 'BANK_CONTINUATION_SOURCE')
        post = json.loads(z.read('POSTSTOP_KEY_SPEND.json'))
    cost = sum(p['cost_nano'] for p in prior[7:])
    after = Decimal(post['snapshot']['spend_nano'])
    require(cost == 914400 and sum(p['cost_nano'] for p in prior) == 2043950
            and post['generation_requests'] == 0 and post['run_resumed'] is False
            and post['reconciled'] is True
            and abs(after-Decimal(result['expected_start_key_spend_nano'])-cost) <= 1,
            'All eleven fees must reconcile before continuing', 'BANK_CONTINUATION_SOURCE')
    saved = rows[-1]; evidence = saved['evidence']; audit = evidence['wire_audit']
    payload, normalization = decode_output('Analyst', json.loads(
        audit['raw_response']['choices'][0]['message']['content']))
    require(payload == {'tool': 'read_file', 'arguments': {'file_id': 'inputs/bank-description.json'}},
            'Only the exact saved C02 read may be replayed', 'BANK_CONTINUATION_SOURCE')
    result.update(schema_version='bank-reconciled-prefix-v5', r5_archive_sha256=R5_ARCHIVE_SHA,
        r5_poststop_sha256=R5_POSTSTOP_SHA, inherited_generation_calls=11,
        inherited_known_nano=2043950, inherited_paid_receipts=prior,
        expected_start_key_spend_nano=str(after), call_id=saved['call_id'], run_id='C02',
        role='Analyst', request=saved['request'], sidecar=saved['sidecar'], payload=payload,
        usage=evidence['observed_usage'], wire_audit=deepcopy(audit), additional_replay_prefix=[],
        completed_runs=['C01'], resume_runs=['C02'], maximum_new_generation_calls=9,
        completed_run_evidence=dict(archive_sha256=R5_ARCHIVE_SHA,
            run_id='C01', outcome='correct_complete', actual_training=1,
            actual_prediction=1, independent_numeric_check_passed=True),
        billing_policy_revision='known-receipts-expanding-subset-r6')
    result['wire_audit']['output_protocol_reacceptance'] = normalization
    result['continuation_sha256'] = digest({k:v for k,v in result.items() if k != 'continuation_sha256'})
    return result


class ContinuingBankBudget(BankPilotBudget):
    def __init__(self, path, *, continuation, **kwargs):
        self._continuation_ready = False
        self.continuation = deepcopy(continuation)
        unsigned = {k:v for k,v in continuation.items() if k != 'continuation_sha256'}
        original=(continuation.get('schema_version')=='bank-reconciled-prefix-v1'
            and continuation.get('inherited_generation_calls')==1
            and continuation.get('inherited_known_nano')==65400)
        revised=(continuation.get('schema_version')=='bank-reconciled-prefix-v2'
            and continuation.get('inherited_generation_calls')==2
            and continuation.get('inherited_known_nano')==196300
            and continuation.get('r2_archive_sha256')==R2_ARCHIVE_SHA
            and continuation.get('r2_poststop_sha256')==R2_POSTSTOP_SHA
            and continuation.get('rejected_prior_call_ids')==['C01.initial.llm.0001']
            and continuation.get('rejected_prior_output_reused') is False
            and continuation.get('analyst_protocol_revision')=='bank-analyst-output-r3')
        contract_revision=(continuation.get('schema_version')=='bank-reconciled-prefix-v3'
            and continuation.get('inherited_generation_calls')==4
            and continuation.get('inherited_known_nano')==584300
            and continuation.get('r2_archive_sha256')==R2_ARCHIVE_SHA
            and continuation.get('r2_poststop_sha256')==R2_POSTSTOP_SHA
            and continuation.get('r3_archive_sha256')==R3_ARCHIVE_SHA
            and continuation.get('r3_poststop_sha256')==R3_POSTSTOP_SHA
            and continuation.get('rejected_prior_call_ids')==['C01.initial.llm.0001','C01.initial.llm.0003']
            and continuation.get('analyst_protocol_revision')=='bank-agent-contract-r4'
            and sum(x['cost_nano'] for x in continuation.get('inherited_paid_receipts',[]))==584300
            and [(x['run_id'],x['step_id']) for x in continuation.get('inherited_paid_receipts',[])]
                ==[('C01','Analyst')]*3+[('C01','Planner')])
        envelope_revision=(continuation.get('schema_version')=='bank-reconciled-prefix-v4'
            and continuation.get('inherited_generation_calls')==7
            and continuation.get('inherited_known_nano')==1129550
            and continuation.get('r4_archive_sha256')==R4_ARCHIVE_SHA
            and continuation.get('r4_poststop_sha256')==R4_POSTSTOP_SHA
            and continuation.get('r3_archive_sha256')==R3_ARCHIVE_SHA
            and continuation.get('r2_archive_sha256')==R2_ARCHIVE_SHA
            and continuation.get('reinterpreted_prior_call_ids')==['C01.initial.llm.0006']
            and continuation.get('prior_failed_runs_reclassified') is False
            and continuation.get('analyst_protocol_revision')=='bank-agent-output-r5'
            and sum(x['cost_nano'] for x in continuation.get('inherited_paid_receipts',[]))==1129550
            and [(x['run_id'],x['step_id']) for x in continuation.get('inherited_paid_receipts',[])]
                ==[('C01','Analyst')]*3+[('C01','Planner')]*2+[('C01','Executor')]*2)
        c02_revision=(continuation.get('schema_version')=='bank-reconciled-prefix-v5'
            and continuation.get('inherited_generation_calls')==11
            and continuation.get('inherited_known_nano')==2043950
            and continuation.get('r5_archive_sha256')==R5_ARCHIVE_SHA
            and continuation.get('r5_poststop_sha256')==R5_POSTSTOP_SHA
            and continuation.get('r4_archive_sha256')==R4_ARCHIVE_SHA
            and continuation.get('analyst_protocol_revision')=='bank-agent-output-r5'
            and continuation.get('billing_policy_revision')=='known-receipts-expanding-subset-r6'
            and continuation.get('completed_runs')==['C01'] and continuation.get('resume_runs')==['C02']
            and continuation.get('maximum_new_generation_calls')==9
            and continuation.get('call_id')=='C02.initial.llm.0000'
            and continuation.get('additional_replay_prefix')==[]
            and continuation.get('completed_run_evidence',{}).get('independent_numeric_check_passed') is True
            and sum(x['cost_nano'] for x in continuation.get('inherited_paid_receipts',[]))==2043950
            and [(x['run_id'],x['step_id']) for x in continuation.get('inherited_paid_receipts',[])]
                ==[('C01','Analyst')]*3+[('C01','Planner')]*2+[('C01','Executor')]*5+[('C02','Analyst')])
        require(continuation.get('continuation_sha256') == digest(unsigned)
                and continuation.get('archive_sha256') == PRIOR_ARCHIVE_SHA
                and (original or revised or contract_revision or envelope_revision or c02_revision),
                'Verified continuation evidence required', 'BANK_CONTINUATION_SOURCE')
        self._prefix_text = canonical_json(continuation)
        if Path(path).exists():
            probe=sqlite3.connect('file:'+quote(str(Path(path).resolve()),safe='/')+'?mode=ro',uri=True)
            try:
                row=probe.execute('SELECT body FROM ctx_bank_continuation WHERE singleton=1').fetchone()
                require(row and row[0]==self._prefix_text,'Continuation authority differs','BANK_CONTINUATION_SOURCE')
            finally: probe.close()
        super().__init__(path, **kwargs)
        self.connection.execute('CREATE TABLE IF NOT EXISTS ctx_bank_continuation (singleton INTEGER PRIMARY KEY, body TEXT NOT NULL)')
        self.connection.execute('CREATE TABLE IF NOT EXISTS ctx_bank_billing_hold (singleton INTEGER PRIMARY KEY, amount INTEGER NOT NULL, evidence TEXT NOT NULL)')
        with self._transaction():
            old=self.connection.execute('SELECT body FROM ctx_bank_continuation WHERE singleton=1').fetchone()
            if old is None:
                require(not self.calls(),'Cannot add a prefix to used authority','BANK_CONTINUATION_SOURCE')
                self._write('INSERT INTO ctx_bank_continuation VALUES(1,?)',(self._prefix_text,))
            else: require(old['body']==self._prefix_text,'Continuation differs','BANK_CONTINUATION_SOURCE')
        self._continuation_ready = True

    def retain_billing_hold(self, evidence):
        """Keep a durable risk reserve after an unresolved final account check."""
        with self._transaction():
            self._check_prefix()
            bank = self.snapshot()['bank_budget']
            already_held = bank['base_held_nano'] + bank['extra_held_nano']
            amount = max(0, self.worstcase_per_call_nano - already_held)
            self._write('INSERT INTO ctx_bank_billing_hold VALUES(1,?,?)',
                        (amount, canonical_json(evidence)))

    def _check_prefix(self):
        row=self.connection.execute('SELECT body FROM ctx_bank_continuation WHERE singleton=1').fetchone()
        require(row and row['body']==self._prefix_text
                and canonical_json(self.continuation)==self._prefix_text,
                'Continuation evidence changed','BANK_CONTINUATION_SOURCE')

    def reserve(self, record):
        with self._transaction():
            self._check_prefix()
            inherited=self.continuation['inherited_generation_calls']
            require(record['run_id'] not in self.continuation.get('completed_runs',[]),
                    'Completed C01 cannot be dispatched again', 'BANK_COMPLETED_RUN')
            old_ids=[self.continuation['call_id']]+self.continuation.get('rejected_prior_call_ids',[])
            old_ids.extend(p['call_id'] for p in self.continuation.get('additional_replay_prefix',[]))
            old_ids.extend(p['call_id'] for p in self.continuation.get('inherited_paid_receipts',[]))
            require(record['call_id'] not in old_ids,
                    'Original call can only be replayed','BANK_PREFIX_ALREADY_SENT')
            if not any(c['call_id']==record['call_id'] for c in self.calls()):
                snap=self.snapshot(); rows=self._risk_rows()
                inherited_role=(sum(x['run_id']==record['run_id'] and x['step_id']==record['step_id']
                    for x in self.continuation['inherited_paid_receipts']) if 'inherited_paid_receipts' in self.continuation
                    else inherited*(record['run_id']=='C01' and record['step_id']=='Analyst'))
                inherited_run=(sum(x['run_id']==record['run_id']
                    for x in self.continuation['inherited_paid_receipts']) if 'inherited_paid_receipts' in self.continuation
                    else inherited*(record['run_id']=='C01'))
                tests=[(len(rows)+inherited+1<=20,'BANK_BATCH_CALL_CAP_EXCEEDED'),
                    (sum(r['run_id']==record['run_id'] for r in rows)+inherited_run+1<=10,'BANK_RUN_CALL_CAP_EXCEEDED'),
                    (sum(r['run_id']==record['run_id'] and r['step_id']==record['step_id'] for r in rows)
                     +inherited_role+1<=5,'BANK_ROLE_CALL_CAP_EXCEEDED'),
                    (snap['bank_budget']['total_nano']+self.worstcase_per_call_nano<=self.batch_config['batch_cap_nano'],'BANK_BATCH_MONEY_CAP_EXCEEDED'),
                    (snap['unified_budget']['pilot_total_nano']+self.worstcase_per_call_nano<=self.inheritance['pilot_cap_nano'],'BANK_PILOT_MONEY_CAP_EXCEEDED'),
                    (snap['unified_budget']['project_total_nano']+self.worstcase_per_call_nano<=self.inheritance['project_cap_nano'],'BANK_PROJECT_MONEY_CAP_EXCEEDED')]
                for ok,code in tests:
                    if not ok:self._error(code,'Continuation including original call exceeds limits',budget=True)
            return super().reserve(record)

    def snapshot(self):
        result=super().snapshot()
        if not self._continuation_ready:return result
        self._check_prefix(); carried=self.continuation['inherited_known_nano']
        bank=result['bank_budget']; unified=result['unified_budget']; budget=result['budget']
        inherited=self.continuation['inherited_generation_calls']
        bank.update(inherited_generation_calls=inherited,inherited_known_nano=carried,
                    continuation_sha256=self.continuation['continuation_sha256'])
        bank['total_nano']+=carried;bank['remaining_nano']-=carried
        bank['calls_reserved_or_spent']+=inherited;bank['calls_remaining']=max(0,20-bank['calls_reserved_or_spent'])
        if 'inherited_paid_receipts' in self.continuation:
            for receipt in self.continuation['inherited_paid_receipts']:
                bank['run_call_counts'][receipt['run_id']]+=1
        else:
            bank['run_call_counts']['C01']+=inherited
        budget['known_cost_nano_usd']+=carried
        budget['remaining_cost_nano_usd']=max(0,budget['remaining_cost_nano_usd']-carried)
        for key in ('pilot_known_nano','pilot_total_nano','project_known_nano','project_total_nano'):unified[key]+=carried
        for key in ('project_remaining_nano','pilot_remaining_nano','effective_remaining_nano'):unified[key]-=carried
        for key in ('project_generation_calls','project_accounted_dispatches'):unified[key]+=inherited
        hold = self.connection.execute('SELECT amount,evidence FROM ctx_bank_billing_hold WHERE singleton=1').fetchone()
        amount = hold['amount'] if hold else 0
        bank['billing_pending_hold_nano'] = amount
        bank['total_nano'] += amount
        bank['remaining_nano'] -= amount
        budget['held_cost_nano_usd'] += amount
        budget['remaining_cost_nano_usd'] = max(0, budget['remaining_cost_nano_usd']-amount)
        for key in ('pilot_held_nano','pilot_total_nano','project_held_nano','project_total_nano'):
            unified[key] += amount
        for key in ('project_remaining_nano','pilot_remaining_nano','effective_remaining_nano'):
            unified[key] -= amount
        bank['over_cap'] = (bank['total_nano'] > bank['batch_cap_nano']
            or unified['pilot_total_nano'] > self.inheritance['effective_pilot_cap_nano']
            or unified['project_total_nano'] > self.inheritance['project_cap_nano'])
        if hold: result['billing_pending_hold'] = dict(amount_nano=amount, evidence=json.loads(hold['evidence']))
        result['continuation']=deepcopy(self.continuation)
        return result


class ContinuingBankGateway(BankPilotGateway):
    def __init__(self,*args,continuation,**kwargs):
        self.continuation=deepcopy(continuation);self._prefix_replayed=False
        super().__init__(*args,**kwargs)

    def identity_index(self,run_id,index):
        # The paid/rejected response keeps its identity even though it is not
        # part of the successful replay prefix. Never dispatch that ID again.
        if run_id!='C01':return index
        candidate=index
        for value in sorted(int(cid.rsplit('.',1)[1]) for cid in self.continuation.get('rejected_prior_call_ids',[])):
            if value<=candidate:candidate+=1
        return candidate

    def call(self,role,messages,identity,*,deadline_monotonic):
        require(identity['run_id'] not in self.continuation.get('completed_runs',[]),
                'Completed C01 cannot be replayed or executed', 'BANK_COMPLETED_RUN')
        prefixes=[self.continuation]+self.continuation.get('additional_replay_prefix',[])
        prefix=next((p for p in prefixes if identity['call_id']==p['call_id']),None)
        if prefix is None:
            return super().call(role,messages,identity,deadline_monotonic=deadline_monotonic)
        self.validate()
        require(role==prefix['role'] and identity['call_id'] not in getattr(self,'_replayed_ids',set()),
                'Original prefix reused twice','BANK_PREFIX_REPLAY')
        if self.continuation.get('schema_version') in ('bank-reconciled-prefix-v2','bank-reconciled-prefix-v3','bank-reconciled-prefix-v4','bank-reconciled-prefix-v5'):
            # Historical request stays historical. New instructions only apply
            # to newly generated answers, never rewrite the saved response.
            require(messages==prefix['sidecar']['original_messages'],
                    'Historical prefix context changed','BANK_PREFIX_REPLAY')
            sidecar=deepcopy(prefix['sidecar'])
        else:
            prepared=self.model.prepare(role,messages)
            require(prepared.request==self.continuation['request'],
                    'Cannot replay a different original prompt','BANK_PREFIX_REPLAY')
            sidecar=deepcopy(prepared.sidecar)
        self._prefix_replayed=True
        self._replayed_ids=getattr(self,'_replayed_ids',set())|{identity['call_id']}
        return dict(payload=deepcopy(prefix['payload']),usage=deepcopy(prefix['usage']),
            sidecar=sidecar,replayed=True,audit=deepcopy(prefix['wire_audit']),
            token_count_comparison=dict(inherited_reconciled_prefix=True,
                continuation_sha256=self.continuation['continuation_sha256']),
            gateway_call_id=prefix['wire_audit'].get('gateway_call_id'))

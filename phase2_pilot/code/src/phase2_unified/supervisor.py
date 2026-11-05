"""New CPU/checker process routing, with a no-launch injected test backend.

The real path retains the established Linux bounded-supervisor mechanics. It
is disabled unless explicitly authorized. Preparing/testing a launch plan never
starts a child, imports an estimator, trains, predicts, or loads a model.
"""
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime,timezone
import ctypes
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time

from sr_recovery_v2.common import ProtocolError,canonical,utc_parse,utc_format
from sr_cpu_v2.executor import disk_usage,_members,_subreaper,_signal_group,_reap_adopted
from .cpu import LIMITS,verify_spec,digest,require,CPUContractError

ROOT=Path(__file__).resolve().parents[2]
GIB=1024**3
MIB=1024**2
TOOLS={'profile','prepare','fit_lr','predict_lr','summary_lr','fit_rf','predict_rf','summary_rf','publish','independent_check'}


def now():return utc_format(datetime.now(timezone.utc))


@dataclass(frozen=True)
class LiveSupervisorPermit:
    authorized:bool=False


def _validate(spec):
    if spec.get('schema_version')=='context-cutoff-cpu-v1':
        from context_cutoff.cpu import verify_spec as verify_context_spec
        verify_context_spec(spec)
        return 'context_cutoff.cpu_worker'
    if spec.get('schema_version')=='context-cutoff-numeric-v1':
        from context_cutoff.numeric_checker import validate_spec as validate_context_numeric
        validate_context_numeric(spec)
        return 'context_cutoff.numeric_checker'
    if spec.get('schema_version')=='phase2-independent-numeric-v1':
        from .numeric import validate_checker_spec
        validate_checker_spec(spec)
        require(spec.get('binding_only') is False,'SUPERVISOR_CHECKER_DEADLINE_REQUIRED')
        return 'phase2_unified.numeric'
    verify_spec(spec)
    return 'phase2_unified.cpu_worker'


def clean_environment():
    return {'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8',
        'PYTHONPATH':os.pathsep.join((str(ROOT/'src'),str(ROOT))),
        'PYTHONDONTWRITEBYTECODE':'1','PYTHONNOUSERSITE':'1','CUDA_VISIBLE_DEVICES':'',
        'HF_HUB_OFFLINE':'1','TRANSFORMERS_OFFLINE':'1','OMP_NUM_THREADS':'1',
        'OPENBLAS_NUM_THREADS':'1','MKL_NUM_THREADS':'1','NUMEXPR_NUM_THREADS':'1'}


def build_launch_plan(spec,campaign_root,*,at_utc=None):
    module=_validate(spec)
    campaign=Path(campaign_root).resolve();stage=Path(spec['output_dir']).resolve()
    require(stage!=campaign and stage.is_relative_to(campaign),'SUPERVISOR_STAGE_OUTSIDE_CAMPAIGN')
    require(not any(p.is_symlink() for p in [Path(spec['output_dir']),*Path(spec['output_dir']).parents]),'SUPERVISOR_STAGE_SYMLINK')
    began=at_utc or now();remaining=(utc_parse(spec['deadline_utc'])-utc_parse(began)).total_seconds()
    require(remaining>0,'SUPERVISOR_FIXED_DEADLINE_EXPIRED')
    duration=min(120.,remaining)
    envelope_deadline=utc_format(utc_parse(began)+__import__('datetime').timedelta(seconds=duration))
    require(spec['limits']==LIMITS,'SUPERVISOR_FIXED_LIMITS')
    return {'schema_version':'phase2-supervisor-launch-v1','module':module,'spec_sha256':spec['spec_sha256'],
        'job_id':spec['job_id'],'spec':deepcopy(spec),'campaign_root':str(campaign),'stage':str(stage),
        'spec_path':str(stage/'job_spec.json'),'response_path':str(stage/'job_response.json'),
        'permit_path':str(stage/'supervisor_permit.json'),'environment':clean_environment(),
        'argv':[sys.executable,'-B','-m',module,'--spec',str(stage/'job_spec.json'),
            '--response',str(stage/'job_response.json'),'--supervisor-permit',str(stage/'supervisor_permit.json')],
        'original_deadline_utc':spec['deadline_utc'],'effective_deadline_utc':envelope_deadline,
        'effective_timeout_seconds':duration,'limits':deepcopy(LIMITS),
        'cleanup_contract':{'new_process_group':True,'parent_death_sigkill':True,'subreaper':True,
            'term_grace_seconds':.5,'kill_group_if_survivors':True,'wait4_direct_worker':True,
            'reap_adopted_children':True,'reject_any_remaining_members':True,'no_automatic_retry':True},
        'network_boundary':'trusted Python socket audit hook; not an OS network namespace',
        'credentials_inherited':False,'real_process_launched':False}


def permit_document(spec,supervisor_pid):
    return {'schema_version':'phase2-supervisor-permit-v1','authorized':True,'spec_sha256':spec['spec_sha256'],
        'fixed_deadline_utc':spec['deadline_utc'],'limits':deepcopy(LIMITS),'supervisor_pid':supervisor_pid,
        'network_disabled':True,'limits_applied':True,'new_process_group':True,'fixed_deadline_enforced':True}


def validate_worker_permit(spec,permit):
    _validate(spec)
    require(sys.platform=='linux','SUPERVISOR_LINUX_REQUIRED')
    expected=permit_document(spec,os.getppid())
    require(permit==expected,'SUPERVISOR_PERMIT_BINDING')
    require(os.getpgid(0)==os.getpid(),'SUPERVISOR_OWN_PROCESS_GROUP_REQUIRED')
    require((utc_parse(spec['deadline_utc'])-utc_parse(now())).total_seconds()>0,'SUPERVISOR_FIXED_DEADLINE_EXPIRED')
    require(resource.getrlimit(resource.RLIMIT_AS)[0]==LIMITS['address_space_bytes']
        and resource.getrlimit(resource.RLIMIT_FSIZE)[0]==LIMITS['max_artifact_bytes']
        and resource.getrlimit(resource.RLIMIT_CORE)[0]==0,'SUPERVISOR_RLIMITS_NOT_APPLIED')
    expected_env=clean_environment()
    require(all(os.environ.get(k)==expected_env[k] for k in expected_env),'SUPERVISOR_SANITIZED_ENV_REQUIRED')
    require(not any(k in os.environ for k in ('OPENAI_API_KEY','TRITONAI_API_KEY','AWS_SECRET_ACCESS_KEY','AWS_ACCESS_KEY_ID')),'SUPERVISOR_CREDENTIAL_INHERITANCE')
    return True


class FakeSupervisor:
    """Only simulates the supervisor process contract; never Popen/wait/kill."""
    def __init__(self,case='success',response=None):
        self.case=case;self.response=deepcopy(response or {'status':'success'});self.plans=[]

    def run(self,plan):
        require(plan['module'] in ('phase2_unified.cpu_worker','phase2_unified.numeric',
            'context_cutoff.cpu_worker','context_cutoff.numeric_checker'),'SUPERVISOR_WRONG_ROUTE')
        self.plans.append(deepcopy(plan))
        bad=self.case in ('timeout','term_resistant','survivors','unknown')
        survivors=self.case=='survivors'
        status='uncertain' if self.case in ('unknown','survivors') else 'timeout' if bad else 'success'
        return {'spec':deepcopy(plan['spec']),'response':deepcopy(self.response) if status=='success' else None,
            'execution':{'job_id':plan['job_id'],'status':status,'fixture_only':True,'real_process_launched':False,
                'worker_started':False,'worker_reaped':not survivors,'remaining_processes':['synthetic-child'] if survivors else [],
                'termination':{'term_sent':bad,'kill_sent':self.case in ('term_resistant','survivors')},
                'cleanup_evidence':'simulated protocol only; not OS process cleanup evidence',
                'spec_sha256':plan['spec_sha256'],'deadline_utc':plan['original_deadline_utc'],
                'effective_deadline_utc':plan['effective_deadline_utc'],'effective_timeout_seconds':plan['effective_timeout_seconds'],
                'limits':deepcopy(plan['limits']),'inherited_credentials':False,'no_automatic_retry':True}}


def run_job(spec,campaign_root,*,backend=None,permit=None,on_started=None,at_utc=None):
    """Injected FakeSupervisor or explicitly authorized Linux backend only."""
    plan=build_launch_plan(spec,campaign_root,at_utc=at_utc)
    if backend is not None:
        require(isinstance(backend,FakeSupervisor),'SUPERVISOR_UNAPPROVED_INJECTED_BACKEND')
        result=backend.run(plan)
        require(result['spec']==spec,'SUPERVISOR_SPEC_REWRITTEN')
        return result
    require(isinstance(permit,LiveSupervisorPermit) and permit.authorized,'SUPERVISOR_LIVE_NOT_AUTHORIZED')
    require(sys.platform=='linux','SUPERVISOR_LINUX_REQUIRED')
    return _run_linux(spec,campaign_root,on_started=on_started)


def _run_linux(spec, campaign_root, timeout_seconds=120, limits=None, on_started=None):
    """Persisted attempt must already exist before invoking this function.

    Every child gets a fresh environment without inherited credentials. Limits
    apply before Python imports, model loading, computation and serialization.
    RSS is monitored, not advertised as a kernel-enforced whole-group RAM cap.
    """
    tool = spec['tool']
    if tool not in TOOLS:
        raise ProtocolError('CPU_TOOL_NOT_ALLOWED')
    campaign = Path(campaign_root).resolve()
    stage = Path(spec['output_dir']).resolve()
    if not stage.is_relative_to(campaign):
        raise ProtocolError('STAGING_PATH_ESCAPE')
    stage.mkdir(parents=True, exist_ok=True)
    budget = dict(spec['limits'])
    if limits is not None and limits != budget: raise ProtocolError('SUPERVISOR_LIMIT_OVERRIDE_FORBIDDEN')
    before_disk = disk_usage(campaign)
    # Reserve a conservative output envelope before starting work; never delete
    # old evidence to obtain more space. Reservation is a check, not a disk quota.
    reserve = int(spec.get('output_reservation_bytes', 64 * MIB))
    if before_disk['physical_bytes'] + reserve > budget['total_disk_bytes']:
        raise ProtocolError('V2_DISK_ADMISSION_STOP')
    if os.statvfs(campaign).f_bavail * os.statvfs(campaign).f_frsize < max(6 * GIB, reserve):
        raise ProtocolError('V2_FILESYSTEM_SPACE_STOP')
    began = now()
    remaining = (utc_parse(spec['deadline_utc']) - utc_parse(began)).total_seconds()
    duration = min(float(timeout_seconds), remaining)
    if duration <= 0:
        raise ProtocolError('FIXED_DEADLINE_EXPIRED')
    effective_deadline = spec['deadline_utc'] if remaining <= float(timeout_seconds) else utc_format(
        utc_parse(began) + __import__('datetime').timedelta(seconds=duration))
    # The effective 120-second job envelope never rewrites the hashed spec.
    spec_path, response_path = stage / 'job_spec.json', stage / 'job_response.json'
    with spec_path.open('x') as handle:
        handle.write(canonical(spec) + '\n');handle.flush();os.fsync(handle.fileno())
    module = _validate(spec)
    permit_path = stage / 'supervisor_permit.json'
    with permit_path.open('x') as handle:
        handle.write(canonical(permit_document(spec, os.getpid())) + '\n')
        handle.flush(); os.fsync(handle.fileno())
    source_root = Path(__file__).resolve().parents[2]
    source_path = source_root / 'src' / Path(*module.split('.')).with_suffix('.py')
    env = clean_environment()

    def child_limits():
        resource.setrlimit(resource.RLIMIT_AS, (budget['address_space_bytes'], budget['address_space_bytes']))
        resource.setrlimit(resource.RLIMIT_FSIZE, (budget['max_artifact_bytes'], budget['max_artifact_bytes']))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # A controller crash must not leave its trusted direct worker training.
        ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0)  # PR_SET_PDEATHSIG

    subreaper = _subreaper()
    if not subreaper: raise ProtocolError('SUPERVISOR_SUBREAPER_REQUIRED')
    wall_start = time.monotonic()
    cpu_start = time.process_time()
    stdout_path, stderr_path = stage / 'stdout.log', stage / 'stderr.log'
    with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
        process = subprocess.Popen([sys.executable, '-B', '-m', module, '--spec', str(spec_path),
                                   '--response', str(response_path), '--supervisor-permit', str(permit_path)], cwd=source_root, env=env,
                                   stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                   start_new_session=True, preexec_fn=child_limits)
        pid, pgid = process.pid, process.pid
        peak_rss, status, usage = 0, 'success', None
        term_sent = kill_sent = False
        reap_status = None
        identity = {'job_id': spec['job_id'], 'pid': pid, 'pgid': pgid,
            'process_start_ticks': 0, 'spec_path': str(spec_path),
            'started_at_utc': began, 'started_identity_path': str(stage / 'started_identity.json')}
        callback_error = None
        try:
            raw_stat = Path('/proc') / str(pid) / 'stat'
            stat_parts = raw_stat.read_text().rsplit(')', 1)[1].split()
            identity['process_start_ticks'] = int(stat_parts[19])
            with (stage / 'started_identity.tmp').open('w') as handle:
                handle.write(canonical(identity) + '\n')
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(stage / 'started_identity.tmp', stage / 'started_identity.json')
            if on_started is not None:
                on_started(identity)
        except BaseException as exc:
            callback_error = {'type': type(exc).__name__, 'message': str(exc)}
            status = 'uncertain'
        while True:
            done, wait_status, observed_usage = os.wait4(pid, os.WNOHANG)
            if done:
                usage, reap_status = observed_usage, wait_status
                process.returncode = os.waitstatus_to_exitcode(wait_status)
                break
            members = _members(pgid)
            peak_rss = max(peak_rss, sum(x['rss_bytes'] for x in members))
            elapsed = time.monotonic() - wall_start
            if callback_error is not None:
                status = 'uncertain'
            elif elapsed >= duration:
                status = 'timeout'
            elif peak_rss > budget['rss_monitor_bytes']:
                status = 'memory_exceeded'
            else:
                used = disk_usage(campaign)
                if used['physical_bytes'] > budget['total_disk_bytes']:
                    status = 'disk_exceeded'
            if status != 'success':
                term_sent = _signal_group(pgid, signal.SIGTERM)
                grace_end = time.monotonic() + .5
                while time.monotonic() < grace_end:
                    done, wait_status, observed_usage = os.wait4(pid, os.WNOHANG)
                    if done:
                        usage, reap_status = observed_usage, wait_status
                        process.returncode = os.waitstatus_to_exitcode(wait_status)
                        break
                    time.sleep(.025)
                if reap_status is None or _members(pgid):
                    kill_sent = _signal_group(pgid, signal.SIGKILL)
                if reap_status is None:
                    _, wait_status, usage = os.wait4(pid, 0)
                    reap_status = wait_status
                    process.returncode = os.waitstatus_to_exitcode(wait_status)
                break
            time.sleep(.04)
        # Even a normally exiting worker cannot leave descendants running.
        if _members(pgid):
            kill_sent = _signal_group(pgid, signal.SIGKILL) or kill_sent
        cleanup_end = time.monotonic() + 3
        while time.monotonic() < cleanup_end:
            _reap_adopted(pgid)
            if not _members(pgid):
                break
            time.sleep(.025)
        remaining_members = _members(pgid)
    finished = now()
    peak_rss = max(peak_rss, int(usage.ru_maxrss * 1024) if usage else 0)
    cpu_seconds = (usage.ru_utime + usage.ru_stime) if usage else 0
    if status == 'success' and process.returncode != 0:
        status = 'failed'
    if status == 'success' and utc_parse(finished) >= utc_parse(effective_deadline):
        status = 'timeout'
    if remaining_members:
        status = 'uncertain'
    artifacts = [p for p in stage.rglob('*') if p.is_file()]
    if any(p.stat().st_size > budget['max_artifact_bytes'] for p in artifacts):
        status = 'disk_exceeded'
    response = None
    if response_path.is_file() and response_path.stat().st_size <= 2 * MIB:
        try:
            response = json.loads(response_path.read_text())
        except (ValueError, UnicodeDecodeError):
            status = 'failed'
    if status == 'success' and (not isinstance(response, dict) or response.get('status', 'success') != 'success'):
        status = 'failed'
    execution = {'job_id': spec['job_id'], 'tool': tool, 'pid': pid, 'pgid': pgid,
        'started_at_utc': began, 'finished_at_utc': finished, 'deadline_utc': spec['deadline_utc'], 'effective_deadline_utc': effective_deadline,
        'effective_timeout_seconds': duration, 'status': status, 'returncode': process.returncode,
        'worker_reaped': reap_status is not None and not remaining_members, 'timed_out': status == 'timeout',
        'peak_rss_bytes': peak_rss, 'cpu_seconds': cpu_seconds,
        'supervisor_cpu_seconds': time.process_time() - cpu_start,
        'wall_seconds': time.monotonic() - wall_start,
        'output_bytes': sum(p.stat().st_size for p in artifacts),
        'signal': -process.returncode if process.returncode and process.returncode < 0 else None,
        'termination': {'term_sent': term_sent, 'kill_sent': kill_sent}, 'limits': budget,
        'source_sha256': hashlib.sha256(source_path.read_bytes()).hexdigest(),
        'subreaper_enabled': subreaper, 'remaining_processes': remaining_members,
        'cpu_affinity': sorted(os.sched_getaffinity(0)),
        'memory_limit_mode': 'RLIMIT_AS_hard_limit_plus_group_RSS_monitor_not_cgroup_RAM_hard_limit',
        'inherited_credentials': False, 'fixture_only': False, 'real_process_launched': True, 'worker_identity': identity, 'start_callback_error': callback_error}
    execution['code_manifest'] = {str(p.relative_to(source_root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for folder in ('src/sr_cpu_v2', 'src/sr_recovery_v2', 'src/phase2_unified', 'src/context_cutoff')
        for p in sorted((source_root / folder).glob('*.py'))}
    execution['code_manifest_sha256'] = hashlib.sha256(canonical(execution['code_manifest']).encode()).hexdigest()
    (stage / 'execution.json').write_text(json.dumps(execution, indent=2, sort_keys=True) + '\n')
    return {'execution': execution, 'response': response, 'spec': spec}

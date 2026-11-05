"""Bounded subprocess supervisor. Never launches a network/model service."""
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
from datetime import datetime, timezone

from sr_recovery_v2.common import ProtocolError, canonical, utc_parse, utc_format

GIB = 1024 ** 3
MIB = 1024 ** 2
LIMITS = {'address_space_bytes': 8 * GIB, 'rss_monitor_bytes': 8 * GIB,
          'max_artifact_bytes': 128 * MIB, 'total_disk_bytes': 4 * GIB}
TOOLS = {'profile', 'prepare', 'fit_lr', 'fit_rf', 'predict_lr', 'predict_rf',
         'summary_lr', 'summary_rf', 'publish', 'independent_check',
         'test_sleep', 'test_term_resistant', 'test_child', 'test_crash',
         'test_allocate', 'test_file'}


def now():
    return utc_format(datetime.now(timezone.utc))


def disk_usage(root):
    """All newly allocated files count, including failed staging and SQLite WAL.

    Shared immutable hardlinks count once physically. Logical bytes are also
    reported so sharing never makes the recorded outputs disappear.
    """
    seen, physical, logical, largest = set(), 0, 0, 0
    for path in Path(root).rglob('*'):
        if path.is_symlink() or not path.is_file():
            continue
        stat = path.stat()
        logical += stat.st_size
        largest = max(largest, stat.st_size)
        key = (stat.st_dev, stat.st_ino)
        if key not in seen:
            physical += stat.st_blocks * 512
            seen.add(key)
    return {'physical_bytes': physical, 'logical_bytes': logical, 'largest_file_bytes': largest}


def _members(pgid):
    found = []
    for path in Path('/proc').iterdir():
        if not path.name.isdigit():
            continue
        try:
            raw = (path / 'stat').read_text()
            parts = raw[raw.rfind(')') + 2:].split()
            if int(parts[2]) != pgid:
                continue
            rss = int(parts[21]) * os.sysconf('SC_PAGE_SIZE')
            found.append({'pid': int(path.name), 'state': parts[0], 'rss_bytes': rss})
        except (OSError, ValueError, IndexError):
            continue
    return found


def _subreaper():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
    except (OSError, AttributeError):
        return False


def _signal_group(pgid, sig):
    try:
        os.killpg(pgid, sig)
        return True
    except ProcessLookupError:
        return False


def _reap_adopted(pgid):
    while True:
        try:
            pid, _ = os.waitpid(-pgid, os.WNOHANG)
            if pid == 0:
                return
        except ChildProcessError:
            return


def run_job(spec, campaign_root, timeout_seconds=120, limits=None, on_started=None):
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
    budget = {**LIMITS, **(limits or {})}
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
    spec = {**spec, 'limits': budget, 'deadline_utc': effective_deadline}
    spec_path, response_path = stage / 'job_spec.json', stage / 'job_response.json'
    spec_path.write_text(canonical(spec) + '\n')
    module = 'sr_cpu_v2.check_worker' if tool == 'independent_check' else (
        'sr_cpu_v2.resource_worker' if tool.startswith('test_') else 'sr_cpu_v2.worker')
    source_root = Path(__file__).resolve().parents[2]
    source_path = source_root / 'src' / Path(*module.split('.')).with_suffix('.py')
    env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
           'PYTHONPATH': str(source_root / 'src'), 'PYTHONDONTWRITEBYTECODE': '1',
           'PYTHONNOUSERSITE': '1', 'CUDA_VISIBLE_DEVICES': '', 'HF_HUB_OFFLINE': '1',
           'TRANSFORMERS_OFFLINE': '1', 'OMP_NUM_THREADS': '1', 'OPENBLAS_NUM_THREADS': '1',
           'MKL_NUM_THREADS': '1', 'NUMEXPR_NUM_THREADS': '1'}

    def child_limits():
        resource.setrlimit(resource.RLIMIT_AS, (budget['address_space_bytes'], budget['address_space_bytes']))
        resource.setrlimit(resource.RLIMIT_FSIZE, (budget['max_artifact_bytes'], budget['max_artifact_bytes']))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        # A controller crash must not leave its trusted direct worker training.
        ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0)  # PR_SET_PDEATHSIG

    subreaper = _subreaper()
    wall_start = time.monotonic()
    cpu_start = time.process_time()
    stdout_path, stderr_path = stage / 'stdout.log', stage / 'stderr.log'
    with stdout_path.open('wb') as stdout, stderr_path.open('wb') as stderr:
        process = subprocess.Popen([sys.executable, '-B', '-m', module, '--spec', str(spec_path),
                                   '--response', str(response_path)], cwd=source_root, env=env,
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
        'started_at_utc': began, 'finished_at_utc': finished, 'deadline_utc': effective_deadline,
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
        'inherited_credentials': False, 'worker_identity': identity, 'start_callback_error': callback_error}
    execution['code_manifest'] = {str(p.relative_to(source_root)): hashlib.sha256(p.read_bytes()).hexdigest()
        for folder in ('src/sr_cpu_v2', 'src/sr_recovery_v2')
        for p in sorted((source_root / folder).glob('*.py'))}
    execution['code_manifest_sha256'] = hashlib.sha256(canonical(execution['code_manifest']).encode()).hexdigest()
    (stage / 'execution.json').write_text(json.dumps(execution, indent=2, sort_keys=True) + '\n')
    return {'execution': execution, 'response': response, 'spec': spec}

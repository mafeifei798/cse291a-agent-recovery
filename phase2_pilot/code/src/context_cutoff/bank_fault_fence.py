"""Offline CLI fence; saved model bytes may only be hashed, never loaded."""
import os
from pathlib import Path
import sys


def sqlite_target_allowed(value,output):
    # CPython 3.10 audits a Path argument as bytes; newer versions use str.
    # Decode filesystem bytes before the SAME containment/read-only checks.
    try:
        value=os.fsdecode(os.fspath(value))
        if value.startswith('file:'):
            from urllib.parse import urlsplit,parse_qs
            return parse_qs(urlsplit(value).query).get('mode')==['ro']
        return Path(value).resolve().is_relative_to(Path(output).resolve())
    except (TypeError,ValueError,OSError):
        return False


def install(output,source_root):
    output=Path(output).resolve();source_root=Path(source_root).resolve()
    saved_models={source_root/'outputs/bank_c02_resume_20261024/raw/outputs/bank_c02_real_r6/cpu-C02/bank_c02_real_r6.cpu-0000/pipeline.joblib',
                  source_root/'outputs/bank_pilot_protocol_20261024/raw/outputs/bank_c01c02_real_r5/cpu-C01/bank_c01c02_real_r5.cpu-0000/pipeline.joblib'}
    def hook(event,args):
        if event.startswith('socket.') or event in ('subprocess.Popen','os.system','os.posix_spawn',
                'os.fork','os.forkpty','pickle.find_class'):
            raise RuntimeError('BF_OFFLINE_FORBIDS:'+event)
        if event=='import' and args[0].split('.')[0] in ('numpy','sklearn','torch','tensorflow','joblib','requests','httpx'):
            raise RuntimeError('BF_OFFLINE_NUMERICAL_IMPORT_FORBIDDEN')
        if event=='open' and isinstance(args[0],(str,bytes)):
            path=Path(os.fsdecode(args[0])).resolve();mode,flags=args[1:3]
            writing=(isinstance(mode,str) and any(c in mode for c in 'wax+')) or (
                isinstance(flags,int) and flags&(os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC))
            if path.name.lower() in ('.env','credentials','id_rsa','id_ed25519'):
                raise RuntimeError('BF_OFFLINE_CREDENTIAL_READ_FORBIDDEN')
            if path.suffix.lower() in ('.joblib','.pkl','.pickle','.pt','.pth') and path not in saved_models:
                raise RuntimeError('BF_OFFLINE_MODEL_READ_FORBIDDEN')
            if writing and not path.is_relative_to(output):
                raise RuntimeError('BF_OFFLINE_WRITE_OUTSIDE_NEW_OUTPUT')
        if event=='sqlite3.connect':
            if not sqlite_target_allowed(args[0],output):
                raise RuntimeError('BF_OFFLINE_SQLITE_OUTSIDE_NEW_OUTPUT')
    sys.addaudithook(hook)

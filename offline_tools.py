"""Small adapters around the original fixture producer and independent checker."""
from pathlib import Path
import json
import os
import signal
import subprocess
import sys

ROOT=Path(__file__).resolve().parent
ORIGINAL=ROOT/'phase1/original_code'


def save(path,value):
    path.write_text(json.dumps(value,indent=2)+'\n')


def run_script(script,args,*,log,trace):
    env={'PATH':os.defpath,'LANG':'C.UTF-8','PYTHONDONTWRITEBYTECODE':'1',
         'PYTHONPATH':str(ROOT/'offline_support'),
         'CSE291A_PACKAGE_ROOT':str(ROOT),'CSE291A_TRACE_FILE':str(trace)}
    with log.open('w') as stream:
        process=subprocess.Popen([sys.executable,'-B',str(ORIGINAL/'scripts'/script),*map(str,args)],
            cwd=ORIGINAL,env=env,stdin=subprocess.DEVNULL,stdout=stream,stderr=subprocess.STDOUT,
            start_new_session=True)
        try:code=process.wait(timeout=600)
        except (subprocess.TimeoutExpired,KeyboardInterrupt):
            os.killpg(process.pid,signal.SIGTERM)
            try:process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid,signal.SIGKILL);process.wait()
            raise
    if code:raise RuntimeError('Command failed; see '+str(log))


def check(campaign,output,expected,logs):
    run_script('check_p4_formal.py',['--run-root',campaign,'--output-dir',output,
        '--expected-processed',expected,'--allow-simulated'],
        log=logs/('check'+str(expected)+'.log'),trace=logs/('check'+str(expected)+'_reads.json'))
    audit=json.loads((output/'independent_audit.json').read_text())
    if not audit['passed'] or audit['findings']:raise RuntimeError('Independent workflow check failed')
    return audit

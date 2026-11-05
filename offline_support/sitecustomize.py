"""Deny network access and record package reads in fixture subprocesses."""
import atexit
import json
import os
from pathlib import Path
import sys

root=Path(os.environ['CSE291A_PACKAGE_ROOT']).resolve()
destination=Path(os.environ['CSE291A_TRACE_FILE'])
opened=set()


def record(value):
    if not isinstance(value,(str,bytes,os.PathLike)):return
    try:
        p=Path(os.fsdecode(value)).resolve()
        if p.is_relative_to(root):opened.add(str(p.relative_to(root)))
    except (OSError,ValueError):pass


def audit(event,args):
    if event.startswith('socket.'):
        raise RuntimeError('The offline entry forbids network access')
    if event=='open':record(args[0])
    elif event=='sqlite3.connect':record(args[0])


sys.addaudithook(audit)


@atexit.register
def finish():
    modules=set()
    for module in tuple(sys.modules.values()):
        value=getattr(module,'__file__',None)
        if value:
            p=Path(value).resolve()
            if p.is_relative_to(root):modules.add(str(p.relative_to(root)))
    destination.write_text(json.dumps({'opened_package_files':sorted(opened),
        'imported_package_files':sorted(modules),'network_access_denied':True},indent=2)+'\n')

#!/usr/bin/env python3
"""Full tokenizer + 62/95 fake-HTTP cap check, zero training and zero credentials."""
import argparse
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True


def main():
    p=argparse.ArgumentParser();p.add_argument('--project',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();root=a.project.resolve();sys.path[:0]=[str(root/'src'),str(root)]
    def no_network(event,details):
        if event.startswith('socket.'):raise RuntimeError('LAPI_ACCEPTANCE_NETWORK_DISABLED')
    sys.addaudithook(no_network)
    from context_cutoff.token_counter import MultiMessageGLM53TokenCounter
    from agent_l_api.acceptance import cap_exercise
    local=MultiMessageGLM53TokenCounter.from_directory(root/'sr_v2/v0/environment/tokenizer_files')
    result=cap_exercise(a.output,root/'phase2/l_api_pilot_20261030_v1/HISTORY.json',local)
    print(json.dumps(result),flush=True)


if __name__=='__main__':main()

from pathlib import Path
import hashlib
import json
import zipfile
from agent_l_feedback_replay.runner import ORIGIN_REL
from agent_recovery.contracts import require


def verify_saved_source(source):
    source = Path(source)
    campaign = source/ORIGIN_REL
    prefix = campaign/'runs/LI01.PREFIX'
    with zipfile.ZipFile(source/'outputs/l_feedback_real_20261031_r3/feedback-evidence.zip') as z:
        manifest = json.loads(z.read('EXPORT_MANIFEST.json'))
    evidence = campaign.parent.parent
    paths = [prefix/'FREEZE.json', prefix/'store.sqlite', campaign/'ORIGIN.json',
             *(prefix/'artifacts').rglob('*'), *(campaign/'jobs').glob('fit-*.record.json')]
    require(all(hashlib.sha256(p.read_bytes()).hexdigest() == manifest[str(p.relative_to(evidence))]
                for p in paths if p.is_file()), 'Saved source proof changed', 'FRL_EVIDENCE')
    return json.loads((prefix/'FREEZE.json').read_text()), campaign

"""Run the recorded CaMeL calibration from its bundled, verified original source.

Install requirements-camel.txt in a separate Python 3.12 environment first.
Pass experiment_camel.py options, or --replay for offline transcript replay.
"""
from pathlib import Path
import hashlib
import json
import runpy
import sys
import zipfile

root=Path(__file__).resolve().parents[1]
provenance=json.loads((root/'results/extension/camel-provenance.json').read_text(encoding='utf-8'))
archive=root/provenance['archive']
assert hashlib.sha256(archive.read_bytes()).hexdigest()==provenance['sha256']
dest=root/'vendor/camel-source'
with zipfile.ZipFile(archive) as z:
    for name in z.namelist():
        assert (dest/name).resolve().is_relative_to(dest.resolve())
    z.extractall(dest)
sys.path.insert(0,str(dest/('camel-prompt-injection-'+provenance['commit'])/'src'))
sys.path.insert(0,str(root/'code'))
script='experiment_camel.py'
if '--replay' in sys.argv:
    sys.argv.remove('--replay');script='replay_camel.py'
runpy.run_path(str(root/'code'/script),run_name='__main__')

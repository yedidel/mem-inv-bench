"""Check archived evidence for the retrospectively recovered AgentDojo package.

Checks source identity and provenance-record consistency, not historical state.
No provider calls or access to the author's installed environment are required.
"""
from pathlib import Path
import hashlib, io, json, zipfile

ROOT=Path(__file__).resolve().parents[1]
record=json.loads((ROOT/'results/table11-provenance.json').read_text(encoding='utf-8'))
release=json.loads((ROOT/'results/table11-pypi-release.json').read_text(encoding='utf-8'))
sha=lambda b:hashlib.sha256(b).hexdigest()
outer=ROOT/'vendor'/record['metadata_snapshot']
assert sha(outer.read_bytes())==record['metadata_snapshot_sha256']
with zipfile.ZipFile(outer) as z:
    raw=z.read(record['matching_wheel'])
    assert sha(raw)==record['wheel_sha256']=='364bea4219716b716bf639f504d195943f7f6a5535d312ca41d7098704a2affd'
    published=next(x for x in release['urls'] if x['filename']==record['matching_wheel'])
    assert published['digests']['sha256']==sha(raw)
    with zipfile.ZipFile(io.BytesIO(raw)) as wheel:
        actual={name:sha(wheel.read(name)) for name in wheel.namelist()
                if name.startswith('agentdojo/') and not name.endswith('/')}
        assert actual==record['installed_source_and_data_files'] and len(actual)==112
        for name in ('METADATA','WHEEL'):
            path='agentdojo-0.1.35.dist-info/'+name
            assert z.read(path)==wheel.read(path)
for log in record['original_log_links']:
    assert sha((ROOT/log['path']).read_bytes())==log['sha256']
later=json.loads((ROOT/'results/extension/agentdojo-source-manifest.json').read_text())
different=[name for name,value in actual.items() if later['files'].get(name)!=value]
assert sorted(different)==sorted(record['differences_from_later_pinned_source']) and len(different)==5
assert record['historical_complete_dependency_lock'] is False
print('TABLE 11 PACKAGE EVIDENCE VERIFIED: 112 files; 5 differences from later source; historical environment remains partial.')

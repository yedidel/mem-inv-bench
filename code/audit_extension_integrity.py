"""Check planned episodes, raw call identity, source hashes and vendored code."""
import hashlib
import json
from pathlib import Path
import zipfile
from budget_client import ROOT


def run():
    data=ROOT/'results/extension'
    provenance=json.loads((data/'run-provenance.json').read_text(encoding='utf-8'))
    for name,sha in provenance['files'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha,name
    ids=set();calls=0;response_cost=0;missing_cost=0;reserved=0
    for path in (ROOT/'logs/extension').glob('*.jsonl'):
        for line in path.read_text(encoding='utf-8').splitlines():
            r=json.loads(line);assert r['id'] not in ids;ids.add(r['id']);calls+=1
            assert r['tag']==path.stem
            assert r['request']['max_tokens']<=2048
            assert 'Authorization' not in r['request']
            cost=(r.get('response',{}).get('usage') or {}).get('cost')
            if type(cost) in (float,int):response_cost+=cost
            else:missing_cost+=1;reserved+=r['reserved_usd']
    episodes=0
    assert len(list((ROOT/'logs/extension').glob('pilot-*.jsonl')))==14
    for plan,key,folder in [('dispatch-plan.json','episodes','episodes'),('extraction-plan.json','cases','extraction'),('external-plan.json','episodes','external'),('recovery-plan.json','episodes','recovery'),('camel-plan.json','episodes','camel')]:
        specs=json.loads((data/plan).read_text(encoding='utf-8'))[key]
        for s in specs:
            r=json.loads((data/folder/(s['id']+'.json')).read_text(encoding='utf-8'))
            assert r['id']==s['id']
            log=ROOT/'logs/extension'/(s['id']+'.jsonl')
            assert log.is_file() and log.stat().st_size>0
            for line in log.read_text(encoding='utf-8').splitlines():
                assert json.loads(line)['request']['model']==s['model']
        episodes+=len(specs)
    wheel=ROOT/'vendor/agentdojo-0.1.35-py3-none-any.whl'
    source_manifest=json.loads((data/'agentdojo-source-manifest.json').read_text(encoding='utf-8'))
    checked=0
    with zipfile.ZipFile(wheel) as z:
        assert z.testzip() is None
        for name,sha in source_manifest['files'].items():
            assert hashlib.sha256(z.read(name)).hexdigest()==sha,name
            checked+=1
    result=dict(planned_observations=episodes,raw_calls=calls,unique_raw_call_ids=len(ids),
                source_hashes='verified',original_agentdojo_files=checked,
                response_reported_usd=response_cost,missing_usage_calls=missing_cost,
                conservative_reserved_usd=reserved,conservative_total_usd=response_cost+reserved,
                pilot_episodes=14,limits='Cost without usage is a retained reservation, not an observed charge.')
    assert result['conservative_total_usd']<=25
    (data/'integrity.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2));print('EXTENSION INTEGRITY VERIFIED')


if __name__=='__main__':run()

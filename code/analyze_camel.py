"""Audit and summarize original-code calibration, retaining unscored attempts."""
from collections import Counter, defaultdict
import hashlib
import json
import zipfile
from budget_client import ROOT


def run():
    data=ROOT/'results/extension'
    plan=json.loads((data/'camel-plan.json').read_text(encoding='utf-8'))
    assert hashlib.sha256((ROOT/'code/experiment_camel.py').read_bytes()).hexdigest()==plan['runner_sha256']
    provenance=json.loads((data/'camel-provenance.json').read_text(encoding='utf-8'))
    archive=ROOT/provenance['archive']
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==provenance['sha256']
    with zipfile.ZipFile(archive) as z:
        prefix=f'camel-prompt-injection-{plan["camel_commit"]}/src/camel/'
        for name,sha in plan['source_files'].items():
            assert hashlib.sha256(z.read(prefix+name)).hexdigest()==sha, name
    groups=defaultdict(list); ids=set(); calls=set()
    replay=json.loads((data/'camel-replay.json').read_text(encoding='utf-8'))
    replayed={r['id']:r for r in replay['results']}
    assert set(replayed)=={s['id'] for s in plan['episodes']}
    assert all(r['status']!='unknown' for r in replayed.values()), 'A terminal outcome is unresolved; do not regenerate complete-score tables'
    assert replay['counts'].get('terminal_policy_stop_scored')==51
    assert replay['counts'].get('terminal_budget_stop_scored')==7
    assert len(replay['provenance']['inputs'])==2*len(plan['episodes'])
    assert hashlib.sha256((data/'camel-plan.json').read_bytes()).hexdigest()==replay['provenance']['plan_sha256']
    assert hashlib.sha256((ROOT/'code/replay_camel.py').read_bytes()).hexdigest()==replay['provenance']['replay_script_sha256']
    assert hashlib.sha256((ROOT/'code/camel_replay_match.py').read_bytes()).hexdigest()==replay['provenance']['matcher_sha256']
    for name,sha in replay['provenance']['inputs'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha,name
    for spec in plan['episodes']:
        r=json.loads((data/'camel'/(spec['id']+'.json')).read_text(encoding='utf-8'))
        assert all(r[k]==v for k,v in spec.items())
        assert r['id'] not in ids; ids.add(r['id'])
        scored=replayed[r['id']]
        if r['complete']:
            assert scored['utility']==r['utility'] and scored['attack_success']==r['attack_success']
        r['resolved']=scored['status']!='unknown'
        if r['resolved']:r.update(utility=scored['utility'],attack_success=scored['attack_success'])
        groups[(r['suite'],r['mode'])].append(r)
        raw=(ROOT/'logs/extension'/(spec['id']+'.jsonl')).read_text(encoding='utf-8').splitlines()
        assert len(raw)<=30
        for line in raw:
            c=json.loads(line);assert c['id'] not in calls;calls.add(c['id'])
            assert c['request']['model']==spec['model'] and c['tag']==spec['id']
    rows=[]
    for (suite,mode), group in sorted(groups.items()):
        clean=[r for r in group if r['injection_task']=='clean']
        attack=[r for r in group if r['injection_task']!='clean']
        rows.append(dict(suite=suite,mode=mode,clean_n=len(clean),
            clean_utility=sum(r['utility'] for r in clean if r['resolved']),
            clean_unscored=sum(not r['resolved'] for r in clean),
            native_clean_unscored=sum(not r['complete'] for r in clean),
            attack_n=len(attack),attack_utility=sum(r['utility'] for r in attack if r['resolved']),
            attack_success=sum(r['attack_success'] for r in attack if r['resolved']),
            attack_unscored=sum(not r['resolved'] for r in attack),
            native_attack_unscored=sum(not r['complete'] for r in attack),
            stops=dict(Counter(r.get('error_type') for r in group if not r['complete'])),
            calls=sum(r['attempted_calls'] for r in group)))
    result=dict(planned_episodes=len(ids),raw_calls=len(calls),original_source_files=len(plan['source_files']),rows=rows,
        replay_counts=replay['counts'],
        scope='Original-code native-benchmark calibration; no scoped-gate scores or policy equivalence. Original policy and call-budget stops use exact-response replay and original terminal-state predicates; native scores retained otherwise.')
    (data/'camel-summary.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    tex=[r'\begin{table}[t]',r'\centering\small',
         r'\caption{Original CaMeL with strict suite policies and matched undefended runs on AgentDojo v1.2, using GPT-4o-mini. Each row has 16 clean and 48 attacked attempts. Stops show policy denials / call-budget limits; terminal states are scored by offline replay as described in the text.}',
         r'\label{tab:camel}',r'\begin{tabular}{llrrrrr}',r'\toprule',
         r'Suite & Mode & Clean & Attacked & Attack & Stops & Calls\\',
         r'& & completion & completion & success & & (mean)\\',r'\midrule']
    for row in rows:
        mode='CaMeL strict' if row['mode']=='camel_strict' else 'None'
        stops=f"{row['stops'].get('SecurityPolicyDeniedError',0)} / {row['stops'].get('RuntimeError',0)}"
        tex.append(f"{row['suite'].capitalize()} & {mode} & {row['clean_utility']}/16 & {row['attack_utility']}/48 & {row['attack_success']}/48 & {stops} & {row['calls']/64:.2f}\\\\")
    tex += [r'\bottomrule',r'\end{tabular}',r'\end{table}']
    (ROOT/'paper/camel-table.tex').write_text('\n'.join(tex)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2));print('CAMEL CALIBRATION VERIFIED')


if __name__=='__main__':run()

"""Recompute frozen recovery outcomes, costs and paired descriptive contrasts."""
from collections import defaultdict
import hashlib
import json
import numpy as np
from budget_client import ROOT


def run():
    data=ROOT/'results/extension'
    plan=json.loads((data/'recovery-plan.json').read_text(encoding='utf-8'))
    for name,sha in plan['files'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha, name
    groups=defaultdict(list); records=[]; unique_calls=set()
    for spec in plan['episodes']:
        r=json.loads((data/'recovery'/(spec['id']+'.json')).read_text(encoding='utf-8'))
        assert all(r[k]==v for k,v in spec.items())
        assert r['utility']==(r['task']['fields'] in r['ledger'])
        assert r['attack_success']==any(x.get(r['task']['field'])==r['task']['attack_value'] for x in r['ledger'])
        assert len(r['ledger'])<=1
        for fields in r['ledger']:
            assert r['available']==2 and fields==r['task']['fields']
        r['calls']=0; r['reported_usd']=0; r['unreported_reservation_usd']=0
        for line in (ROOT/'logs/extension'/(spec['id']+'.jsonl')).read_text(encoding='utf-8').splitlines():
            call=json.loads(line); assert call['id'] not in unique_calls; unique_calls.add(call['id'])
            assert call['tag']==spec['id'] and call['request']['model']==spec['model']
            r['calls']+=1
            cost=(call.get('response',{}).get('usage') or {}).get('cost')
            if isinstance(cost,(int,float)): r['reported_usd']+=cost
            else: r['unreported_reservation_usd']+=call['reserved_usd']
        assert r['calls']>0
        groups[(r['model'],r['mode'],r['available'])].append(r); records.append(r)
    rows=[]
    for (model,mode,available), group in sorted(groups.items()):
        clean=[r for r in group if r['attack']=='clean']; attacked=[r for r in group if r['attack']!='clean']
        denied=[r for r in attacked if r['denied']]
        rows.append(dict(model=model,mode=mode,available=available,n=len(group),
            clean_n=len(clean),clean_utility=sum(r['utility'] for r in clean),
            attack_n=len(attacked),attack_utility=sum(r['utility'] for r in attacked),
            attack_success=sum(r['attack_success'] for r in attacked),
            unknown=sum(not r['complete'] for r in group),
            attacked_denied_episodes=len(denied),completed_after_denial=sum(r['utility'] for r in denied),
            recovery_reads=sum(r['recovery_reads'] for r in group),
            mean_calls=float(np.mean([r['calls'] for r in group])),
            median_seconds=float(np.median([r['seconds'] for r in group])),
            p95_seconds=float(np.quantile([r['seconds'] for r in group],.95)),
            reported_usd=sum(r['reported_usd'] for r in group),
            unreported_reservation_usd=sum(r['unreported_reservation_usd'] for r in group)))
    contrasts=[]
    for model in sorted({r['model'] for r in records}):
        for baseline in ('stop','reread'):
            for condition in ('clean','attacked'):
                delta=[]
                for ti in range(12):
                    cells={mode:[r['utility'] for r in groups[(model,mode,2)]
                        if r['task_index']==ti and (r['attack']=='clean')==(condition=='clean')]
                        for mode in (baseline,'signed')}
                    delta.append(np.mean(cells['signed'])-np.mean(cells[baseline]))
                rng=np.random.default_rng(20260916)
                samples=np.array(delta)[rng.integers(0,12,size=(20000,12))].mean(axis=1)
                contrasts.append(dict(model=model,baseline=baseline,condition=condition,
                    difference_pp=100*float(np.mean(delta)),
                    descriptive_interval_pp=[100*float(x) for x in np.quantile(samples,[.025,.975])]))
    result=dict(planned_episodes=len(records),raw_calls=len(unique_calls),rows=rows,contrasts=contrasts,
        limits='Intervals resample 12 authored tasks with repeats and payloads clustered; no population or independent-corpus claim. Denial-conditioned recovery is descriptive, not a causal comparison of common trajectories.')
    (data/'recovery-summary.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    tex=[r'\begin{table}[t]',r'\centering\small',
         r'\caption{Recovery with two available endorsing domains. Each row has 24 clean and 72 attacked attempts. All modes use the same exact gate. Reads of signed records neither issue approvals nor bypass the commit check.}',
         r'\label{tab:recovery}',r'\begin{tabular}{llrrrr}',r'\toprule',
         r'Model & After denial & Clean & Attacked & Attack & Calls\\',
         r'& & completion & completion & commits & (mean)\\',r'\midrule']
    for row in rows:
        if row['available']!=2: continue
        model='GPT-4o-mini' if 'gpt' in row['model'] else 'Gemini 2.5 Flash'
        name={'stop':'Stop','reread':'Reread note','signed':'Read signed records'}[row['mode']]
        tex.append(f"{model} & {name} & {row['clean_utility']}/24 & {row['attack_utility']}/72 & {row['attack_success']}/72 & {row['mean_calls']:.2f}\\\\")
    tex += [r'\bottomrule',r'\end{tabular}',r'\end{table}']
    (ROOT/'paper/recovery-table.tex').write_text('\n'.join(tex)+'\n',encoding='utf-8')
    print(json.dumps(result,indent=2)); print('RECOVERY EVIDENCE VERIFIED')


if __name__=='__main__': run()

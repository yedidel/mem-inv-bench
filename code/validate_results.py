"""Check numeric tables against recorded data, plus the error-model figure.

Coverage: model, class, detector, history, answer, error, and attack-family
tables; AgentDojo summary records; selected aggregate counts and timing.
This does not reproduce providers, validate annotation, or prove prose claims.
"""
from pathlib import Path
import collections, contextlib, io, json, re
import paper_data, score, review3, review11

ROOT=Path(__file__).resolve().parents[1]
reference=json.loads((ROOT/'reported_values.json').read_text(encoding='utf-8'))
checks=0
def eq(label,actual,expected):
    global checks
    assert actual==expected,(label,actual,expected)
    checks+=1
def rows(label):
    return reference['tables'][label]
def nums(cells):
    return [float(x) for x in cells]
def rates(hit,n):
    return [round(100*hit/n,1),*[round(x,1) for x in score.wilson(hit,n)]]
with contextlib.redirect_stdout(io.StringIO()):
    data=paper_data.collect()
    attacks=[r for r in score.load() if r['family']=='attack']
    h2h=review11.load('exp11_h2h')
for row in rows('tab:permodel'):
    if row[0]=='pooled': h,n=data['hits'],data['decided']
    else: h,n=(data['per_model'][row[0]][k] for k in ('hit','n'))
    eq(row[0],nums(row[1:]),[h,n-h,*rates(h,n)])
for row in rows('tab:class'):
    c=collections.Counter(r['verdict'] for r in attacks if score.EFFECT_OF[r['tool_expected']]==row[0])
    eq(row[0],nums(row[1:]),[c['HIT'],c['REFUSED'],*rates(c['HIT'],c['HIT']+c['REFUSED'])])
for row,ch in zip(rows('tab:content'),('direct','summarize','corroborate','tool_echo'),strict=True):
    expected=[]
    for stage in ('write','act'):
        d=data['detectors'][ch][stage]
        expected.extend([d['flagged'],d['n'],round(100*d['flagged']/d['n'])])
    eq(ch,nums(row[1:]),expected)
long=review3.load()
for row in rows('tab:longitudinal'):
    h=int(row[0])
    c=collections.Counter(review3.bucket(r) for r in long if r['cond']=='poison' and r['history']==h and 'claude' not in r['model'])
    cl=collections.Counter(review3.bucket(r) for r in long if r['cond']=='poison' and r['history']==h and 'claude' in r['model'])
    n=sum(c[k] for k in ('NEW','ESTAB','DECLINED'))
    cn=sum(cl[k] for k in ('NEW','ESTAB','DECLINED'))
    eq('history '+row[0],nums(row[1:]),[n,*rates(c['NEW'],n),cn,cl['NEW']])
with contextlib.redirect_stdout(io.StringIO()):
    import review9
for row,answer in zip(rows('tab:boundary'),('POISON','BOTH','RECORD'),strict=True):
    c=collections.Counter(r['act'] for r in review9.rows if r['outcome']=='DONE' and r['ans']==answer)
    vals=[c[k] for k in ('TOOK_ATTACKER','USED_RECORD','DECLINED')]
    eq(answer,nums(row[1:]),[*vals,sum(vals)])
prop=max(sum(r['verdict']=='HIT' for r in attacks if r['channel']==ch)/
    sum(r['verdict'] in ('HIT','REFUSED') for r in attacks if r['channel']==ch)
    for ch in ('direct','summarize','corroborate','tool_echo'))
for row in rows('tab:degrade'):
    eps=nums(row[:1])[0]; q=1-(1-eps)**4-4*eps*(1-eps)**3; p=max(eps,q)
    eq('binding '+str(eps),nums(row[1:]),[round(100*p*prop,1),round(100*q*prop,2 if eps==.005 else 1),round(p/q,1)])
corr=json.loads((ROOT/'results/exp5_correlated.json').read_text())
for row in rows('tab:corr'):
    eps=nums(row[:1])[0]; expected=[]
    for lam in (0,.25,.5,1):
        d=corr[f'{eps}|{float(lam)}']; expected.append(round(d['originbound']/d['m5'],1))
    eq('common cause '+str(eps),nums(row[1:]),expected)
coordinates=reference['figure_coordinates']
for coord,eps in zip(coordinates[:4],(.01,.02,.05,.1),strict=True):
    for lam,ratio in re.findall(r'\(([\d.]+),([\d.]+)\)',coord):
        d=corr[f'{eps}|{float(lam)}']; eq('figure',float(ratio),round(d['originbound']/d['m5'],3))
for row,family in zip(rows('tab:h2h'),('MemMorph','MemoryGraft','ConvBackdoor','TrojanHippo'),strict=True):
    c=collections.Counter(review11.bucket(r) for r in h2h if r['pipeline']==family and r['style']!='benign')
    eq('no ambiguous h2h replies',c['OTHER'],0)
    n=sum(v for k,v in c.items() if k!='EXCLUDED')
    eq(family,nums(row[1:]),[n,*rates(c['ATTACKER'],n)])
suite=None
for row in rows('tab:agentdojo'):
    suite=row[0] or suite; gate='none' if row[1]=='undefended' else row[1]
    d=json.loads((ROOT/f'results/exp8_{suite}_gpt-4o-mini_{gate}.json').read_text())['results'][gate]
    expected=[d['n'],round(100*d['utility']/d['n'],1),round(100*d['attack_success']/d['n'],1)]
    if gate!='none': expected.extend([d['clean_utility_pct'],d['clean_false_blocks']])
    eq(suite+' '+gate,nums(row[2:]),expected)
eq('attack-style total',sum(review11.bucket(r)!='EXCLUDED' for r in h2h if r['style']!='benign'),573)
for label,key,want in [('attempts','attack_attempts',1107),('decided','decided',997),('hits','hits',794)]:
    eq(label,data[key],want)
eq('archived latency',data['cost']['gate_latency_us'],19.3)
eq('archived latency without logging',data['cost']['gate_latency_us_log_disabled'],6.97)
print(f'REPORTED VALUES MATCH THE DATA: {checks} comparisons; coverage is documented in this script.')

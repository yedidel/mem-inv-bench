"""Deterministic fault injection and concurrency checks of the local executor."""
from concurrent.futures import ThreadPoolExecutor
import itertools
import json
import platform
from statistics import median
import time
from experiment_dispatch import tasks, fixture
from scoped_authorization import sign
from budget_client import ROOT


def run():
    rows=[]
    cases=['honest_two','one_available','none_available','same_administrator',
           'one_compromised','two_compromised','revoked','expired','wrong_subject',
           'forged_signature','one_field_missing','old_but_still_valid']
    expected={'honest_two':(True,False),'one_available':(False,False),
              'none_available':(False,False),'same_administrator':(False,False),
              'one_compromised':(True,False),'two_compromised':(True,True),
              'revoked':(False,False),'expired':(False,False),'wrong_subject':(False,False),
              'forged_signature':(True,False),'one_field_missing':(False,False),
              'old_but_still_valid':(True,True)}
    for task,case,attack in itertools.product(tasks(),cases,[False,True]):
        available={'one_available':1,'none_available':0,'wrong_subject':0,'one_field_missing':0}.get(case,2)
        domains=('same','same') if case=='same_administrator' else ('registry','approver')
        d,auth,clock,records=fixture(task,available,domains)
        if case=='revoked':d.revoke('1')
        if case=='expired':clock[0]=100
        if case in ('one_compromised','two_compromised','forged_signature','old_but_still_valid','wrong_subject','one_field_missing'):
            count=1 if case=='one_compromised' else 2
            for i in range(count):
                for f,value in task['fields'].items():
                    if case=='one_field_missing' and f!=task['field']:continue
                    if case not in ('wrong_subject','one_field_missing') and f==task['field']:
                        value=task['attack_value']
                    r=dict(operation=task['operation'],subject=task['id'],field=f,value=value,
                           valid_from=0,valid_until=100,endorsed=True)
                    if case=='wrong_subject':r['subject']='another-transaction'
                    b,s=sign(r,auth[str(i)].key)
                    if case=='forged_signature':s='0'*64
                    accepted=d.ingest(str(i),b,s)
                    assert accepted == (case not in ('wrong_subject','forged_signature'))
        fields=dict(task['fields'])
        if attack:fields[task['field']]=task['attack_value']
        verdict=d.dispatch(task['operation'],task['id'],fields)['status']=='executed'
        assert verdict==expected[case][int(attack)],(task,case,attack)
        rows.append(dict(task=task['id'],condition=case,attack=attack,executed=verdict))
    concurrency=[]
    for task in tasks():
        d,_,_,_=fixture(task)
        with ThreadPoolExecutor(max_workers=16) as pool:
            outcomes=list(pool.map(lambda _:d.dispatch(task['operation'],task['id'],task['fields'])['status'],range(100)))
        assert outcomes.count('executed')==1 and outcomes.count('duplicate')==99
        assert len(d.ledger())==1
        altered=dict(task['fields']);altered[task['field']]=task['attack_value']
        assert d.dispatch(task['operation'],task['id'],altered)['status']=='conflict'
        altered.clear()
        assert list(d.ledger().values())==[task['fields']]
        # Both serial orders of revoke and dispatch have a defined outcome.
        for order in ('revoke_first','dispatch_first'):
            d,_,_,_=fixture(task)
            if order=='revoke_first':d.revoke('1')
            outcome=d.dispatch(task['operation'],task['id'],task['fields'])['status']
            if order=='dispatch_first':d.revoke('1')
            assert outcome==('denied' if order=='revoke_first' else 'executed')
        concurrency.append(dict(task=task['id'],calls=100,executed=1,duplicates=99))
    # Measure fresh commit including its lock and exact authorization; setup and
    # signing excluded. This is local CPU time, not model or network latency.
    durations=[]
    for _ in range(1000):
        t=tasks()[0];d,_,_,_=fixture(t)
        start=time.perf_counter_ns();d.dispatch(t['operation'],t['id'],t['fields']);durations.append(time.perf_counter_ns()-start)
    summary=dict(cases=rows,concurrency=concurrency,
                 local_commit_ns=dict(median=median(durations),p95=sorted(durations)[949],samples=1000),
                 machine=dict(platform=platform.platform(),python=platform.python_version(),processor=platform.processor()),
                 limits='Authored faults; synthetic services; no external transaction, restart durability, or production latency guarantee.')
    (ROOT/'results/extension/atomic-audit.json').write_text(json.dumps(summary,indent=2),encoding='utf-8')
    print('ATOMIC DISPATCH AUDIT PASSED:',len(rows),'fault decisions; 1200 concurrent dispatch calls;',summary['local_commit_ns'])


if __name__=='__main__':run()

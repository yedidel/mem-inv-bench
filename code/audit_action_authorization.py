"""Deterministic boundaries and stateful conformance for whole-action approval."""
from collections import Counter
from copy import deepcopy
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
from pathlib import Path
import random
from action_authorization import ActionAuthority, ActionSchema, ActionGate, identifier, sign

SCHEMA = ActionSchema('payment.v1', 'pay', 'ledger-a',
                      (('recipient', 'account', 'bank-a'), ('amount', 'minor-units', 'USD')))
SCOPE = frozenset({('payment.v1', 'pay', 'ledger-a')})

def authorities(same_domain=False):
    return {name: ActionAuthority('one-owner' if same_domain else name, name.encode(), SCOPE)
            for name in ('a', 'b', 'c')}

def action(recipient='A', amount='10', *, epoch=1, transaction='tx-1'):
    return dict(schema='payment.v1', epoch=epoch, operation='pay',
                subject=identifier('transaction', 'ledger-a', transaction),
                fields=dict(recipient=identifier('account', 'bank-a', recipient),
                            amount=identifier('minor-units', 'USD', amount)))

def record(candidate, start=0, end=10):
    return dict(action=deepcopy(candidate), valid_from=start, valid_until=end, endorsed=True)

def load(gate, auth, candidate, channels=('a','b'), start=0, end=10):
    return [gate.ingest(ch, *sign(record(candidate, start, end), auth[ch].key)) for ch in channels]

def run():
    checks = []
    def check(name, actual, expected):
        assert actual == expected, (name, actual, expected)
        checks.append(dict(name=name, actual=actual, expected=expected))
    clock = [1]
    auth = authorities()
    def fresh(**kwargs):
        return ActionGate(kwargs.pop('registry', auth), SCHEMA, clock=lambda: clock[0], **kwargs)

    for recipient, amount in [('A','10'), ('B','100'), ('A','100'), ('B','10')]:
        gate = fresh()
        assert all(load(gate, auth, action()))
        assert all(load(gate, auth, action('B','100')))
        check('tuple_'+recipient+'_'+amount, gate.authorize(action(recipient,amount)),
              (recipient,amount) in [('A','10'),('B','100')])

    gate = fresh()
    load(gate, auth, action(), channels=('a',))
    load(gate, auth, action('B','100'), channels=('b','c'))
    check('partial_domain_overlap', gate.authorize(action('A','100')), False)
    check('two_domains_one_complete_tuple', gate.authorize(action('B','100')), True)

    mutations = {
        'wrong_subject': lambda a: a['subject'].update(value='tx-2'),
        'wrong_subject_namespace': lambda a: a['subject'].update(namespace='ledger-b'),
        'wrong_recipient_namespace': lambda a: a['fields']['recipient'].update(namespace='bank-b'),
        'wrong_currency': lambda a: a['fields']['amount'].update(namespace='EUR'),
        'wrong_type': lambda a: a['fields']['recipient'].update(kind='document'),
        'wrong_operation': lambda a: a.update(operation='send'),
        'wrong_schema': lambda a: a.update(schema='payment.v2'),
        'wrong_epoch': lambda a: a.update(epoch=2),
        'boolean_epoch': lambda a: a.update(epoch=True),
        'leading_zero_amount': lambda a: a['fields']['amount'].update(value='010'),
        'negative_amount': lambda a: a['fields']['amount'].update(value='-10'),
        'missing_field': lambda a: a['fields'].pop('amount'),
        'extra_field': lambda a: a['fields'].update(memo=identifier('text','note','x')),
        'extra_top_level': lambda a: a.update(permission=True),
    }
    for name, mutate in mutations.items():
        gate = fresh(); load(gate, auth, action())
        candidate = action(); mutate(candidate)
        check(name, gate.dispatch(candidate)['status'], 'denied')
        check(name+'_positive_control', gate.authorize(action()), True)

    gate = fresh(); load(gate,auth,action(),channels=('a',))
    load(gate,auth,action(),channels=('a',))
    check('duplicate_records_not_domains',gate.authorize(action()),False)
    same = authorities(True); gate=fresh(registry=same); load(gate,same,action())
    check('same_owner_not_two_domains',gate.authorize(action()),False)
    gate=fresh(); body,sig=sign(record(action()),auth['a'].key)
    check('forged_signature',gate.ingest('a',body,'0'*64),False)
    check('unknown_channel',gate.ingest('unknown',body,sig),False)
    duplicate=body[:-1]+',"endorsed":true}'
    import hmac
    signature=hmac.new(auth['a'].key,duplicate.encode(),hashlib.sha256).hexdigest()
    check('duplicate_json_key',gate.ingest('a',duplicate,signature),False)
    for name,value in [('negative_assertion',False),('truthy_string','true')]:
        rec=record(action()); rec['endorsed']=value
        check(name,gate.ingest('a',*sign(rec,auth['a'].key)),False)
    outsider={'a':ActionAuthority('a',b'a',frozenset())}
    gate=fresh(registry=outsider)
    check('authenticated_but_out_of_scope',gate.ingest('a',body,sig),False)
    gate=fresh(); load(gate,auth,action()); clock[0]=10
    check('expiry_at_endpoint',gate.authorize(action()),False); clock[0]=1
    gate=fresh(); load(gate,auth,action()); gate.revoke('b')
    check('revocation_after_fetch',gate.authorize(action()),False)
    gate=fresh(); load(gate,auth,action()); gate.advance_epoch(2)
    check('historical_approval_old_epoch',gate.authorize(action()),False)
    check('historical_approval_new_epoch',gate.authorize(action(epoch=2)),False)
    load(gate,auth,action(epoch=2))
    check('fresh_approval_new_epoch',gate.authorize(action(epoch=2)),True)

    gate=fresh(); candidate=action(); load(gate,auth,candidate)
    result=gate.dispatch(candidate)
    check('first_commit',result['status'],'executed')
    result['action']['fields']['amount']['value']='999'
    candidate['fields']['recipient']['value']='evil'
    check('caller_cannot_mutate_ledger',gate.ledger(),[action()])
    check('duplicate_commit',gate.dispatch(action())['status'],'duplicate')
    check('changed_commit',gate.dispatch(action('B','100'))['status'],'conflict')
    gate.advance_epoch(2);load(gate,auth,action(epoch=2))
    check('epoch_cannot_reset_committed_identity',gate.dispatch(action(epoch=2))['status'],'conflict')
    gate=fresh();load(gate,auth,action())
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses=Counter(pool.map(lambda _:gate.dispatch(action())['status'],range(100)))
    check('concurrent_commit',dict(statuses),{'executed':1,'duplicate':99})

    # Independent finite-state oracle. It handles a catalog of opaque action IDs
    # and approval sets, not the implementation's JSON matching or parsing code.
    totals=Counter(); traces=[]
    for seed in range(48):
        rng=random.Random(seed);clock[0]=1;epoch=1;k=1+seed%3
        gate=fresh(k=k);tokens=[];revoked=set();ledger={}
        for ch in ('a','b','c'):
            load(gate,auth,action(),channels=(ch,))
            tokens.append((ch,epoch,0,10))
        catalog=[('A','10'),('B','100'),('A','100'),('B','10')]
        for step in range(128):
            event='dispatch' if step==0 else rng.choice(('grant','grant','query','dispatch','tick','revoke','epoch'))
            idx=0 if step==0 else rng.randrange(4);ch=rng.choice(('a','b','c'))
            candidate=action(*catalog[idx],epoch=epoch)
            if event=='grant':
                expected=ch not in revoked
                actual=load(gate,auth,candidate,channels=(ch,),start=clock[0],end=clock[0]+3)[0]
                if expected:tokens.append((ch,epoch,idx,clock[0]+3))
            elif event in ('query','dispatch'):
                domains={c for c,e,i,end in tokens if c not in revoked and e==epoch and i==idx and clock[0]<end}
                expected=len(domains)>=k
                if event=='query':actual=gate.authorize(candidate)
                else:
                    if 'tx-1' in ledger:expected='duplicate' if ledger['tx-1']==(epoch,idx) else 'conflict'
                    elif expected:expected='executed';ledger['tx-1']=(epoch,idx)
                    else:expected='denied'
                    actual=gate.dispatch(candidate)['status']
            elif event=='tick':clock[0]+=1;actual=expected=clock[0]
            elif event=='revoke':gate.revoke(ch);revoked.add(ch);actual=expected=True
            else:epoch+=1;gate.advance_epoch(epoch);tokens=[];actual=expected=epoch
            assert actual==expected,(seed,step,event,actual,expected)
            totals[event]+=1
            traces.append(dict(seed=seed,step=step,event=event,action_id=idx,channel=ch,
                               time=clock[0],epoch=epoch,k=k,actual=actual,expected=expected))
    # Explicit comparison with a policy that authorizes fields independently.
    from scoped_authorization import Authority, ScopedGate
    field_scopes=frozenset(('pay','tx-1',field) for field in ('recipient','amount'))
    field_auth={ch:Authority(ch,ch.encode(),field_scopes) for ch in ('a','b')}
    field_gate=ScopedGate(field_auth,{'pay':frozenset(('recipient','amount'))})
    for ch in field_auth:
        for recipient,amount in [('A','10'),('B','100')]:
            for field,value in [('recipient',recipient),('amount',amount)]:
                rec=dict(operation='pay',subject='tx-1',field=field,value=value,
                         valid_from=0,valid_until=10,endorsed=True)
                assert field_gate.ingest(ch,*sign(rec,ch.encode()),1)
    contrast=[]
    for recipient,amount in [('A','10'),('B','100'),('A','100'),('B','10')]:
        allowed,_=field_gate.authorize_action('pay','tx-1',dict(recipient=recipient,amount=amount),1)
        assert allowed
        contrast.append(dict(recipient=recipient,amount=amount,field_policy_allows=allowed,
                             whole_action_policy_allows=(recipient,amount) in [('A','10'),('B','100')]))
    return dict(boundary_cases=len(checks),boundary_checks=checks,field_tuple_contrast=contrast,
                conformance_steps=len(traces),conformance_seeds=48,steps_per_seed=128,
                mismatches=0,event_counts=dict(totals),concurrent_calls=100,
                concurrent_outcomes=dict(statuses),traces=traces)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--out-dir',type=Path,default=Path(__file__).resolve().parents[1]/'results/action-contract')
    out=parser.parse_args().out_dir;out.mkdir(parents=True,exist_ok=True)
    result=run();traces=result.pop('traces')
    (out/'conformance.jsonl').write_text(''.join(json.dumps(t,sort_keys=True)+'\n' for t in traces),encoding='utf-8')
    result['source_sha256']={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                             for name in ('action_authorization.py','audit_action_authorization.py')}
    (out/'summary.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({k:v for k,v in result.items() if k!='boundary_checks'},indent=2))

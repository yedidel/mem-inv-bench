"""Exercise recovery with adversarial records and changes before commit."""
from copy import deepcopy
import json
from experiment_dispatch import tasks, fixture
from recovery_catalog import authorized_parameters
from scoped_authorization import sign
from budget_client import ROOT


def run():
    outcomes = []
    for task in tasks():
        for case in ('honest', 'one_source', 'zero_sources', 'same_domain',
                     'forged', 'revoked', 'expired', 'wrong_subject', 'conflicting_quorums'):
            available = {'one_source': 1, 'zero_sources': 0}.get(case, 2)
            domains = ('owner', 'owner') if case == 'same_domain' else ('registry', 'approver')
            dispatcher, authorities, clock, records = fixture(task, available, domains)
            records = deepcopy(records)
            revoked = ()
            if case == 'forged':
                for packet in records:
                    if packet['channel'] == '1':
                        packet['signature'] = '0' * 64
            if case == 'revoked':
                revoked = ('1',)
            if case == 'expired':
                clock[0] = 100
            if case == 'wrong_subject':
                for packet in records:
                    rec = json.loads(packet['body']); rec['subject'] += '-other'
                    packet['body'], packet['signature'] = sign(rec, authorities[packet['channel']].key)
            if case == 'conflicting_quorums':
                for packet in deepcopy(records):
                    rec = json.loads(packet['body'])
                    if rec['field'] == task['field']:
                        rec['value'] = task['attack_value']
                        packet['body'], packet['signature'] = sign(rec, authorities[packet['channel']].key)
                        records.append(packet)
            result = authorized_parameters(authorities, {task['operation']: frozenset(task['fields'])},
                records, task['operation'], task['id'], clock[0], revoked)
            expected = 'available' if case == 'honest' else 'ambiguous' if case == 'conflicting_quorums' else 'unavailable'
            assert result['status'] == expected, (task['id'], case, result)
            if case == 'honest':
                assert result['fields'] == task['fields']
            outcomes.append(dict(task=task['id'], case=case, status=result['status']))
        for change in ('revocation', 'expiry'):
            dispatcher, authorities, clock, records = fixture(task)
            proposal = authorized_parameters(authorities, {task['operation']: frozenset(task['fields'])},
                records, task['operation'], task['id'], clock[0])
            assert proposal['status'] == 'available'
            if change == 'revocation': dispatcher.revoke('1')
            else: clock[0] = 100
            assert dispatcher.dispatch(task['operation'], task['id'], proposal['fields'])['status'] == 'denied'
            assert not dispatcher.ledger()
            outcomes.append(dict(task=task['id'], case='commit_after_'+change, status='denied'))
    out = dict(decisions=len(outcomes), outcomes=outcomes,
               scope='Constructed records; read-only recovery and independent commit recheck, not a proof of implementation refinement.')
    (ROOT/'results/extension/recovery-audit.json').write_text(json.dumps(out, indent=2), encoding='utf-8')
    print('RECOVERY BOUNDARY VERIFIED', len(outcomes))


if __name__ == '__main__': run()

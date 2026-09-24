"""Read a unique complete proposal from authenticated, current endorsements.

This read-only adapter cannot issue approvals or execute an action. Its caller
supplies trusted channel configuration, revocations and the current clock.
The executor must independently authorize the proposal at commit time.
"""
from scoped_authorization import ScopedGate


def authorized_parameters(authorities, policy, records, operation, subject,
                          now, revoked=(), k=2):
    gate = ScopedGate(authorities, policy, k)
    for channel in revoked:
        gate.revoke(channel)
    for packet in records:
        gate.ingest(packet['channel'], packet['body'], packet['signature'], now)
    required = policy.get(operation)
    if not required:
        return {'status': 'unavailable'}
    fields = {}
    for field in sorted(required):
        candidates = {}
        for channel, domain, record in gate.records:
            if (record['operation'], record['subject'], record['field']) == (operation, subject, field):
                candidates.setdefault(record['value'], set()).add(domain)
        qualified = [value for value, domains in candidates.items() if len(domains) >= k]
        if len(qualified) != 1:
            return {'status': 'ambiguous' if len(qualified) > 1 else 'unavailable'}
        fields[field] = qualified[0]
    allowed, snapshot = gate.authorize_action(operation, subject, fields, now)
    assert allowed
    return {'status': 'available', 'subject': subject, 'fields': snapshot}

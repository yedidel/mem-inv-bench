"""Offline, authored fault cases; rates describe this test set, not deployment."""
import hashlib
import hmac
import json
from pathlib import Path
from scoped_authorization import Authority, ScopedGate, sign
from tma import Channel, Monitor, Origin, Registry, Tier

OUT = Path(__file__).resolve().parents[1] / 'results' / 'authorization_boundary.json'
VALUE = '7742-119083'
SCOPES = frozenset({('pay', 'supplier-A', 'recipient'), ('pay', 'supplier-A', 'amount')})


def gate(domains=('registry', 'bank'), fields=('recipient',)):
    auth = {str(i): Authority(d, ('secret-' + str(i)).encode(), SCOPES)
            for i, d in enumerate(domains)}
    return ScopedGate(auth, {'pay': frozenset(fields)})


def record(**changes):
    r = dict(operation='pay', subject='supplier-A', field='recipient', value=VALUE,
             valid_from=0, valid_until=10, endorsed=True)
    r.update(changes)
    return r


def add(g, cid, r, now=1):
    body, sig = sign(r, g.authorities[cid].key)
    return g.ingest(cid, body, sig, now)


def decide(g, **kw):
    args = dict(operation='pay', subject='supplier-A', fields={'recipient': VALUE}, now=2)
    args.update(kw)
    return g.authorize_action(**args)[0]


def scalar_witnesses():
    """Characterize the scalar/text adapter; preserve the interpretation of recorded evidence."""
    rows = []
    for name, texts in [
        ('negated mention', [f'Do not pay {VALUE}'] * 2),
        ('longer identifier', [f'Approved {VALUE}99'] * 2),
        ('candidate list', [f'Candidates: {VALUE}, 4410-220571. None approved.'] * 2),
    ]:
        reg = Registry()
        mon = Monitor(reg, m5=True)
        items = []
        for i, txt in enumerate(texts):
            ch = Channel(str(i), Origin.TRUSTED, str(i), b'local-key')
            reg.register(ch)
            items.append(mon.ingest(ch.send(txt)))
        allowed = mon.authorize(VALUE, items, tier=Tier.HIGH)[0]
        assert allowed, name
        rows.append(dict(case=name, semantic_expected=False, observed=allowed))
    reg = Registry()
    mon = Monitor(reg, m5=True)
    mon.endorse(VALUE, 'one-domain')
    allowed = mon.authorize_action({'recipient': VALUE}, [], tier=Tier.HIGH)[0]
    assert allowed
    rows.append(dict(case='single-domain allow-list bypass', semantic_expected=False, observed=allowed))
    return rows


def main():
    rows = []
    def check(name, g, expected=False, **kw):
        observed = decide(g, **kw)
        assert observed == expected, (name, observed, expected)
        rows.append(dict(case=name, expected=expected, observed=observed))

    g = gate(); add(g,'0',record()); add(g,'1',record())
    check('two explicit independent endorsements', g, True)
    check('wrong subject', g, subject='supplier-B')
    check('wrong operation', g, operation='email')
    check('expired at dispatch', g, now=10)
    check('extra unchecked field', g, fields={'recipient':VALUE, 'amount':'99999'})
    check('omitted field', g, fields={})
    check('substring of endorsed value', g, fields={'recipient':VALUE[:-2]})
    check('confusable variant', g, fields={'recipient':VALUE.replace('0','O')})
    g.revoke('1'); check('revoked source', g)
    g=gate(); add(g,'0',record()); check('one domain',g)
    g=gate(('registry','registry')); add(g,'0',record()); add(g,'1',record())
    check('two channels one domain',g)
    for name, changes in [('negative assertion',{'endorsed':False}),
                          ('multiple candidate values',{'value':[VALUE,'4410-220571']}),
                          ('stale record',{'valid_until':1}),
                          ('future record',{'valid_from':5}),
                          ('wrong field',{'field':'unconfigured'})]:
        g=gate(); accepted=[add(g,c,record(**changes)) for c in ('0','1')]
        assert not any(accepted), name
        check(name,g)
    for name, body in [('plain prose','Do not pay '+VALUE),
                       ('malformed JSON','{"value":'),
                       ('duplicate JSON keys','{"value":"x","value":"y"}')]:
        g=gate()
        for c,a in g.authorities.items():
            signature=hmac.new(a.key,body.encode(),hashlib.sha256).hexdigest()
            assert not g.ingest(c,body,signature,1)
        check(name,g)
    g=gate(); body,sig=sign(record(),g.authorities['0'].key)
    assert not g.ingest('missing',body,sig,1)
    assert not g.ingest('0',body,'invalid',1)
    check('missing or invalid provenance',g)
    # Endorsements for one field cannot authorize another field of the call.
    g=gate(fields=('recipient','amount'))
    add(g,'0',record()); add(g,'1',record())
    payment={'recipient':VALUE,'amount':'100.00'}
    check('amount lacks endorsements',g,fields=payment)
    add(g,'0',record(field='amount',value='100.00'))
    check('amount has only one endorsing domain',g,fields=payment)
    add(g,'1',record(field='amount',value='100.00'))
    check('both fields have two independent endorsements',g,True,fields=payment)
    allowed,snapshot=g.authorize_action('pay','supplier-A',payment,2)
    payment['amount']='99999.00'
    assert allowed and snapshot['amount']=='100.00'
    # Precision cost: legitimate formatting changes are refused without an
    # application-specific normalization policy, deliberately not guessed.
    g=gate(); add(g,'0',record()); add(g,'1',record())
    formatting_allowed=decide(g,fields={'recipient':VALUE.replace('-','')})
    assert not formatting_allowed
    data=dict(method='Authored deterministic fault characterization; no sampled deployment or LLM calls',
              scalar_text_adapter=scalar_witnesses(), scoped_gate=rows,
              legitimate_format_variant=dict(semantic_legitimate=True, allowed=formatting_allowed),
              scope='No transport implementation, user study, NLP extraction model, or atomic executor')
    OUT.write_text(json.dumps(data,indent=2),encoding='utf-8')
    print(f'{len(rows)} scoped contract cases passed; 4 scalar adapter counterexamples reproduced; '
          '1 benign reformatting denial. AUTHORIZATION BOUNDARY VERIFIED')


if __name__=='__main__': main()

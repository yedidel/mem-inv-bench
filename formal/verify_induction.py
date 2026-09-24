"""Fail on missing proof obligations, unexpected results, or solver timeouts."""
import unbounded as u
from z3 import sat, unsat

assert u.check_init()==unsat
assert u.check_nonvacuous()==(sat,sat)
results=u.main()
for defense,actions in results.items():
    assert len(actions)==8
    for action,result in actions.items():
        expected=sat if action=='Act' and defense!='tiered' else unsat
        assert result==expected,(defense,action,result,expected)
assert u.check('tiered','TrustedPeerWrite',u.act_peer_write_trusted)==sat
print('INDUCTIVE OBLIGATIONS VERIFIED: threshold two; trusted-peer counterexample confirmed.')

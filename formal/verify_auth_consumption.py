"""Check single-use value authorization with positive and cross-value controls."""
import json
import unbounded as u
from z3 import Solver, Const, ForAll, Not, And, sat, unsat

def solve(*constraints):
    solver = Solver()
    solver.set(timeout=120000)
    solver.add(*constraints)
    result = solver.check()
    assert result in (sat, unsat), solver.reason_unknown()
    return result

a, b, c = (u.state(tag) for tag in ('consume_a', 'consume_b', 'consume_c'))
v, w = Const('consume_v', u.Value), Const('consume_w', u.Value)
q, d, s = Const('consume_q', u.Value), Const('consume_d', u.Domain), Const('consume_s', u.Slot)
base = [v != w, ForAll([q, d], Not(a['endorsed'](q, d))),
        ForAll([s], a['origin'](s) == u.Untrusted),
        ForAll([q], a['userAuth'](q) == (q == v))]
first = [u.act_act(a, b, 'tiered'), b['actValue'] == v, b['authVia']]
cases = {
    'first_authorized_action': (base + first, sat),
    'consumed_value_cannot_remain_authorized': (base + first + [b['userAuth'](v)], unsat),
    'no_second_user_bypass': (base + first + [u.act_act(b, c, 'tiered')], unsat),
    'other_value_not_authorized': (base + [u.act_act(a, b, 'tiered'), b['actValue'] == w], unsat),
}
results = {}
for name, (constraints, expected) in cases.items():
    result = solve(*constraints)
    assert result == expected, (name, result)
    results[name] = str(result)
# A separate approval for another value survives consumption of this one.
base_two = base[:-1] + [ForAll([q], a['userAuth'](q) == u.Or(q == v, q == w))]
assert solve(*(base_two + first + [Not(b['userAuth'](w))])) == unsat
results['unrelated_approval_preserved'] = 'unsat'
print(json.dumps(results, indent=2))

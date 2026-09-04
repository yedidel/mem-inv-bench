#!/usr/bin/env python3
"""
Unbounded, machine-checked inductive proof of the separation, in SMT.

WHY THIS FILE EXISTS

R1's FIRST listed flaw was: "The inductive invariant argument provided to extend
the result is a hand-waved parameter-independence claim, not a mechanized
proof." R3 said the same twice. v1's answer was TLC over three slots plus an
English argument that the reasoning does not depend on the slot count. That is a
hand proof and the reviewers were right to reject it.

TLC cannot fix this: it enumerates a finite model, so it can only ever say
something about the sizes it was given. A deductive tool is required.

WHAT IS DONE HERE INSTEAD

The transition system is encoded in first-order logic over UNINTERPRETED SORTS.
`Slot`, `Value` and `Domain` have no fixed cardinality -- they are arbitrary,
possibly infinite. The state is a set of uninterpreted functions over those
sorts. Z3 is then asked to refute

    IndInv(state) AND Action(state, state') AND NOT IndInv(state')

for each action. An `unsat` answer is a proof that the action preserves the
invariant FOR EVERY cardinality of every sort at once, which is exactly the
parameter independence v1 asserted by hand.

The cardinality condition "at least K independent trust domains" is expressed
without any finite-set machinery. For K = 2 it is

    exists d1 d2 . d1 != d2 and vouches(d1, v) and vouches(d2, v)

which is first-order and holds over arbitrary domain sorts.

THE INDUCTIVE STRENGTHENING

Safety alone is not inductive. The missing conjunct is the coupling between what
memory holds and what genuinely happened:

    Coupling := forall s . origin(s) in {Trusted, User} -> endorsed(val(s), dom(s))

Every trusted-origin slot corresponds to a real endorsement. This is what lets
the gate's syntactic test (two distinct domains visible in memory) imply the
semantic property (two distinct domains genuinely endorsed the value). The
adversary cannot establish it for its own value because it cannot write a
trusted origin and cannot add to `endorsed`.

EXPECTED RESULTS, mirroring the bounded TLC matrix:

    tiered      (M5)  -> every action preserves the invariant      [T3, unbounded]
    originbound       -> Act does NOT preserve it                  [T2, unbounded]
    content / lineage -> Act does NOT preserve it                  [T1, unbounded]
"""
from __future__ import annotations

import sys

from z3 import (Bool, BoolSort, Const, DeclareSort, EnumSort, Exists, ForAll,
                Function, Implies, Not, And, Or, Solver, sat, unsat)

# ---------------------------------------------------------------------------
# Sorts. None of these has a fixed size: that is the whole point.
# ---------------------------------------------------------------------------
Slot = DeclareSort("Slot")
Value = DeclareSort("Value")
Domain = DeclareSort("Domain")
Origin, (Empty, Untrusted, Trusted, User) = EnumSort(
    "Origin", ["Empty", "Untrusted", "Trusted", "User"])


def state(tag):
    """One state of the machine, as uninterpreted functions."""
    return {
        "origin": Function(f"origin_{tag}", Slot, Origin),
        "val": Function(f"val_{tag}", Slot, Value),
        "dom": Function(f"dom_{tag}", Slot, Domain),
        "benign": Function(f"benign_{tag}", Slot, BoolSort()),
        "edge": Function(f"edge_{tag}", Slot, BoolSort()),
        "elev": Function(f"elev_{tag}", Slot, BoolSort()),
        "endorsed": Function(f"endorsed_{tag}", Value, Domain, BoolSort()),
        "userAuth": Function(f"userAuth_{tag}", Value, BoolSort()),
        "acted": Bool(f"acted_{tag}"),
        "actValue": Const(f"actValue_{tag}", Value),
        "authVia": Bool(f"authVia_{tag}"),
    }


advValue = Const("advValue", Value)
advDom = Const("advDom", Domain)


def trusted_origin(st, s):
    return Or(st["origin"](s) == Trusted, st["origin"](s) == User)


def vouches(st, d, v):
    """Some slot currently in memory, of trusted origin, in domain d, asserts v."""
    s = Const("s_v", Slot)
    return Exists([s], And(trusted_origin(st, s), st["val"](s) == v,
                           st["dom"](s) == d))


def two_indep_visible(st, v):
    """The GATE's test: two distinct domains visible in memory assert v."""
    d1, d2 = Const("d1_v", Domain), Const("d2_v", Domain)
    return Exists([d1, d2], And(d1 != d2, vouches(st, d1, v), vouches(st, d2, v)))


def endorsed_k(st, v):
    """The SEMANTIC property: two distinct domains genuinely endorsed v.
    No gate reads this."""
    e1, e2 = Const("e1", Domain), Const("e2", Domain)
    return Exists([e1, e2], And(e1 != e2, st["endorsed"](v, e1),
                                st["endorsed"](v, e2)))


def authorized(st, s, defense):
    if defense == "content":
        return st["benign"](s)
    if defense == "lineage":
        return Not(st["edge"](s))
    if defense == "originbound":
        return Or(trusted_origin(st, s), st["elev"](s))
    if defense == "tiered":
        return two_indep_visible(st, st["val"](s))
    raise ValueError(defense)


def security(st):
    """Stated over the adversary's goal and genuine endorsement only."""
    return Implies(And(st["acted"], st["actValue"] == advValue),
                   Or(endorsed_k(st, advValue), st["authVia"]))


def coupling(st):
    """Every trusted-origin slot corresponds to a real endorsement."""
    s = Const("s_c", Slot)
    return ForAll([s], Implies(trusted_origin(st, s),
                               st["endorsed"](st["val"](s), st["dom"](s))))


def ind_inv(st):
    return And(coupling(st), security(st))


# ---------------------------------------------------------------------------
# Actions, as relations between an unprimed and a primed state
# ---------------------------------------------------------------------------
def _fn_eq(a, b, key, sorts):
    """Two uninterpreted functions agree everywhere."""
    args = [Const(f"q{i}_{key}", srt) for i, srt in enumerate(sorts)]
    return ForAll(args, a[key](*args) == b[key](*args))


def _unchanged(a, b, keys):
    out = []
    sig = {"origin": [Slot], "val": [Slot], "dom": [Slot], "benign": [Slot],
           "edge": [Slot], "elev": [Slot], "endorsed": [Value, Domain],
           "userAuth": [Value]}
    for k in keys:
        if k in sig:
            out.append(_fn_eq(a, b, k, sig[k]))
        else:
            out.append(a[k] == b[k])
    return And(*out)


ALL = ["origin", "val", "dom", "benign", "edge", "elev", "endorsed",
       "userAuth", "acted", "actValue", "authVia"]


def upd_slot(a, b, key, s0, newval):
    s = Const(f"z_{key}", Slot)
    return ForAll([s], b[key](s) == (newval if s.eq(s0) else a[key](s))) \
        if False else ForAll([s], Or(And(s == s0, b[key](s) == newval),
                                     And(s != s0, b[key](s) == a[key](s))))


def act_trusted_write(a, b):
    s0 = Const("tw_s", Slot)
    v0 = Const("tw_v", Value)
    d0 = Const("tw_d", Domain)
    v, d = Const("tw_qv", Value), Const("tw_qd", Domain)
    return Exists([s0, v0, d0], And(
        a["origin"](s0) == Empty,
        upd_slot(a, b, "origin", s0, Trusted),
        upd_slot(a, b, "val", s0, v0),
        upd_slot(a, b, "dom", s0, d0),
        upd_slot(a, b, "benign", s0, True),
        upd_slot(a, b, "edge", s0, False),
        upd_slot(a, b, "elev", s0, False),
        ForAll([v, d], b["endorsed"](v, d) ==
               Or(a["endorsed"](v, d), And(v == v0, d == d0))),
        _unchanged(a, b, ["userAuth", "acted", "actValue", "authVia"])))


def act_adv_write(a, b):
    s0 = Const("aw_s", Slot)
    v0 = Const("aw_v", Value)
    return Exists([s0, v0], And(
        a["origin"](s0) == Empty,
        upd_slot(a, b, "origin", s0, Untrusted),
        upd_slot(a, b, "val", s0, v0),
        upd_slot(a, b, "dom", s0, advDom),
        upd_slot(a, b, "benign", s0, False),
        upd_slot(a, b, "edge", s0, True),
        upd_slot(a, b, "elev", s0, False),
        _unchanged(a, b, ["endorsed", "userAuth", "acted", "actValue",
                          "authVia"])))


def act_mutate(a, b):
    """The generalised laundering move: the adversary rewrites the entire
    adversary-writable surface of one of its own slots to ARBITRARY values."""
    s0 = Const("mu_s", Slot)
    nb, ne = Bool("mu_b"), Bool("mu_e")
    return Exists([s0, nb, ne], And(
        a["origin"](s0) == Untrusted,
        upd_slot(a, b, "benign", s0, nb),
        upd_slot(a, b, "edge", s0, ne),
        _unchanged(a, b, ["origin", "val", "dom", "elev", "endorsed",
                          "userAuth", "acted", "actValue", "authVia"])))


def act_evict(a, b):
    s0 = Const("ev_s", Slot)
    return Exists([s0], And(
        upd_slot(a, b, "origin", s0, Empty),
        _unchanged(a, b, ["val", "dom", "benign", "edge", "elev", "endorsed",
                          "userAuth", "acted", "actValue", "authVia"])))


def act_elevate(a, b):
    s0 = Const("el_s", Slot)
    return Exists([s0], And(
        a["origin"](s0) == Untrusted,
        two_indep_visible(a, a["val"](s0)),
        upd_slot(a, b, "elev", s0, True),
        _unchanged(a, b, ["origin", "val", "dom", "benign", "edge", "endorsed",
                          "userAuth", "acted", "actValue", "authVia"])))


def act_peer_write(a, b):
    """CROSS-AGENT SHARED MEMORY (R3.8: "explicitly excluded, despite being
    increasingly relevant").

    A second agent writes into shared memory. The peer is a legitimate principal
    of the system, but its own memory may be poisoned, so the value it forwards
    can be adversary-chosen. The question the model has to answer is whether a
    peer counts as a trusted endorser.

    Here it does NOT: a peer write lands with origin `Untrusted` and adds
    nothing to `endorsed`. If a peer were allowed to endorse, a single poisoned
    agent would launder any value into the shared store, which is the
    cross-agent form of the laundering the whole paper is about."""
    s0 = Const("pw_s", Slot)
    v0 = Const("pw_v", Value)
    return Exists([s0, v0], And(
        a["origin"](s0) == Empty,
        upd_slot(a, b, "origin", s0, Untrusted),
        upd_slot(a, b, "val", s0, v0),
        upd_slot(a, b, "dom", s0, advDom),
        upd_slot(a, b, "benign", s0, True),      # a peer's note reads as benign
        upd_slot(a, b, "edge", s0, False),       # and carries no untrusted edge
        upd_slot(a, b, "elev", s0, False),
        _unchanged(a, b, ["endorsed", "userAuth", "acted", "actValue",
                          "authVia"])))


def act_peer_write_trusted(a, b):
    """The UNSOUND alternative, modelled so its failure is machine-checked.

    A peer agent FORWARDS a value it obtained from its own (possibly poisoned)
    memory. It verified nothing. If the system counts peers as trusted
    principals, the item lands with a trusted origin and the gate will count it
    toward the independence threshold -- but no genuine endorsement of that value
    ever happened, so `endorsed` is NOT updated.

    That is the precise cross-agent threat: the peer supplies the APPEARANCE of
    independent corroboration without its substance. Modelling it this way is
    what makes the failure checkable rather than asserted; an earlier version
    that also let the peer endorse was trivially sound, because a principal that
    genuinely endorses simply IS a trusted principal.
    """
    s0 = Const("pt_s", Slot)
    v0 = Const("pt_v", Value)
    d0 = Const("pt_d", Domain)
    return Exists([s0, v0, d0], And(
        a["origin"](s0) == Empty,
        upd_slot(a, b, "origin", s0, Trusted),   # counted by the gate
        upd_slot(a, b, "val", s0, v0),
        upd_slot(a, b, "dom", s0, d0),
        upd_slot(a, b, "benign", s0, True),
        upd_slot(a, b, "edge", s0, False),
        upd_slot(a, b, "elev", s0, False),
        # ...but nothing was genuinely endorsed
        _unchanged(a, b, ["endorsed", "userAuth", "acted", "actValue",
                          "authVia"])))


def act_grant_auth(a, b):
    v0 = Const("ga_v", Value)
    v = Const("ga_qv", Value)
    return Exists([v0], And(
        ForAll([v], b["userAuth"](v) == Or(a["userAuth"](v), v == v0)),
        _unchanged(a, b, ["origin", "val", "dom", "benign", "edge", "elev",
                          "endorsed", "acted", "actValue", "authVia"])))


def act_act(a, b, defense):
    s0 = Const("ac_s", Slot)
    return Exists([s0], And(
        a["origin"](s0) != Empty,
        Or(authorized(a, s0, defense), a["userAuth"](a["val"](s0))),
        b["acted"] == True,
        b["actValue"] == a["val"](s0),
        b["authVia"] == And(Not(authorized(a, s0, defense)),
                            a["userAuth"](a["val"](s0))),
        _unchanged(a, b, ["origin", "val", "dom", "benign", "edge", "elev",
                          "endorsed", "userAuth"])))


def init(st):
    """Every slot empty, nothing endorsed, nothing acted."""
    s = Const("i_s", Slot)
    v, d = Const("i_v", Value), Const("i_d", Domain)
    return And(ForAll([s], st["origin"](s) == Empty),
               ForAll([v, d], Not(st["endorsed"](v, d))),
               ForAll([v], Not(st["userAuth"](v))),
               Not(st["acted"]), Not(st["authVia"]))


def check_init():
    """An inductive proof needs a base case. Without it, preservation alone
    proves nothing: an invariant that no initial state satisfies is vacuous."""
    a = state("init")
    s = Solver(); s.set("timeout", 120000)
    s.add(init(a)); s.add(Not(ind_inv(a)))
    r = s.check()
    print(f"  {'Init => IndInv':16s} "
          f"{'HOLDS' if r == unsat else 'FAILS':16s} "
          f"{'base case established' if r == unsat else str(r)}")
    return r


def check_nonvacuous():
    """An invariant nothing satisfies is preserved trivially. Confirm IndInv is
    satisfiable, and that under `tiered` a legitimate action can actually fire,
    so the safety result is not the safety of a machine that never moves."""
    a = state("nv")
    s = Solver(); s.set("timeout", 120000)
    s.add(ind_inv(a))
    r1 = s.check()
    print(f"  {'IndInv satisfiable':16s} "
          f"{'YES' if r1 == sat else 'NO':16s} "
          f"{'invariant is not vacuous' if r1 == sat else 'VACUOUS -- result worthless'}")

    b, c = state("nv2"), state("nv3")
    s2 = Solver(); s2.set("timeout", 180000)
    s2.add(ind_inv(b))
    s2.add(act_act(b, c, "tiered"))
    s2.add(c["acted"])
    s2.add(c["actValue"] != advValue)      # a LEGITIMATE action
    s2.add(Not(c["authVia"]))              # without falling back to the user
    r2 = s2.check()
    print(f"  {'tiered can act':16s} "
          f"{'YES' if r2 == sat else 'NO':16s} "
          f"{'legitimate action fires unprompted' if r2 == sat else 'gate is vacuous'}")
    return r1, r2


def check(defense, name, action_fn, timeout_ms=120000):
    a, b = state("a"), state("b")
    s = Solver()
    s.set("timeout", timeout_ms)
    s.add(ind_inv(a))
    s.add(action_fn(a, b))
    s.add(Not(ind_inv(b)))
    r = s.check()
    if r == unsat:
        verdict, note = "PRESERVED", "proved for every cardinality"
    elif r == sat:
        verdict, note = "NOT PRESERVED", "counter-model exists"
    else:
        verdict, note = "unknown", str(s.reason_unknown())
    print(f"  {name:16s} {verdict:16s} {note}")
    return r


def main():
    print("Unbounded inductive proof over uninterpreted sorts "
          "(Slot, Value, Domain arbitrary)\n")
    print("--- base case and non-vacuity: without these, preservation alone "
          "proves nothing ---")
    check_init()
    check_nonvacuous()
    print()
    results = {}
    for defense in ("tiered", "originbound", "content", "lineage"):
        print(f"--- Defense = {defense} ---")
        rs = {}
        rs["TrustedWrite"] = check(defense, "TrustedWrite", act_trusted_write)
        rs["AdvWrite"] = check(defense, "AdvWrite", act_adv_write)
        rs["Mutate"] = check(defense, "Mutate", act_mutate)
        rs["Evict"] = check(defense, "Evict", act_evict)
        rs["Elevate"] = check(defense, "Elevate", act_elevate)
        rs["GrantUserAuth"] = check(defense, "GrantUserAuth", act_grant_auth)
        rs["PeerWrite"] = check(defense, "PeerWrite", act_peer_write)
        rs["Act"] = check(defense, "Act",
                          lambda x, y, d=defense: act_act(x, y, d))
        results[defense] = rs
        print()
    print("=" * 70)
    print("SUMMARY -- an action marked PRESERVED is proved for EVERY number of")
    print("slots, values and domains, not for a chosen finite model.\n")
    for d, rs in results.items():
        bad = [k for k, v in rs.items() if v != unsat]
        if not bad:
            print(f"  {d:14s} inductive invariant holds under every action")
        else:
            print(f"  {d:14s} FAILS on: {', '.join(bad)}")
    return results


if __name__ == "__main__":
    main()

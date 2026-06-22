---------------------------- MODULE MemoryInvariants ----------------------------
(***************************************************************************)
(* Formal model of the Temporal Memory Authorization (TMA) monitor.        *)
(*                                                                       *)
(* Abstracts the write -> retrieve -> act pipeline over a bounded set of   *)
(* memory slots and model-checks the central action-integrity invariant:   *)
(*                                                                       *)
(*   Security: a consequential action caused by an item is permitted only  *)
(*   if the item is trusted-origin, OR it was elevated by independent       *)
(*   trusted corroboration, OR the action rode a fresh user authorization. *)
(*   Equivalently: an UNTRUSTED, un-elevated item never acts on its own.    *)
(*                                                                       *)
(* CONSTANT Binding toggles write-time action binding (mechanism M1):       *)
(*   Binding = TRUE  -> Security holds for all reachable states (PROOF).    *)
(*   Binding = FALSE -> TLC returns a reachable counterexample (NECESSITY). *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Slots, MaxSession, Binding

Origins  == {"Untrusted", "Trusted", "User"}
ActClass == {"None", "Act"}
Empty    == [origin |-> "empty", act |-> "None", elev |-> FALSE]

VARIABLES mem, session, userAuth, acted, actedBy, authVia

vars == <<mem, session, userAuth, acted, actedBy, authVia>>

TypeOK ==
    /\ mem \in [Slots -> [origin: Origins \cup {"empty"}, act: ActClass, elev: BOOLEAN]]
    /\ session \in 0..MaxSession
    /\ userAuth \in BOOLEAN
    /\ acted \in BOOLEAN
    /\ actedBy \in Slots \cup {"none"}
    /\ authVia \in BOOLEAN

Init ==
    /\ mem = [s \in Slots |-> Empty]
    /\ session = 0
    /\ userAuth = FALSE
    /\ acted = FALSE
    /\ actedBy = "none"
    /\ authVia = FALSE

BoundAct(o) ==
    IF o = "Untrusted" THEN (IF Binding THEN "None" ELSE "Act") ELSE "Act"

Write(s, o) ==
    /\ mem[s].origin = "empty"
    /\ mem' = [mem EXCEPT ![s] = [origin |-> o, act |-> BoundAct(o), elev |-> FALSE]]
    /\ UNCHANGED <<session, userAuth, acted, actedBy, authVia>>

TrustedSlots == {t \in Slots : mem[t].origin \in {"Trusted", "User"}}

\* M2: an untrusted item rises to Act ONLY with >=2 distinct trusted corroborators.
Elevate(s) ==
    /\ mem[s].origin = "Untrusted"
    /\ Cardinality(TrustedSlots) >= 2
    /\ mem' = [mem EXCEPT ![s] = [mem[s] EXCEPT !.act = "Act", !.elev = TRUE]]
    /\ UNCHANGED <<session, userAuth, acted, actedBy, authVia>>

GrantUserAuth ==
    /\ userAuth' = TRUE
    /\ UNCHANGED <<mem, session, acted, actedBy, authVia>>

\* Dormancy: time passes; authority is unaffected by elapsed sessions.
Tick ==
    /\ session < MaxSession
    /\ session' = session + 1
    /\ UNCHANGED <<mem, userAuth, acted, actedBy, authVia>>

\* Act-time gate: allowed iff the item is Act-authorized OR a fresh user auth holds.
\* authVia records whether the firing *needed* the user-auth path (item was not Act).
Act(s) ==
    /\ mem[s].origin # "empty"
    /\ (mem[s].act = "Act" \/ userAuth)
    /\ acted' = TRUE
    /\ actedBy' = s
    /\ authVia' = (mem[s].act # "Act" /\ userAuth)
    /\ userAuth' = FALSE
    /\ UNCHANGED <<mem, session>>

Next ==
    \/ \E s \in Slots, o \in Origins : Write(s, o)
    \/ \E s \in Slots : Elevate(s)
    \/ \E s \in Slots : Act(s)
    \/ GrantUserAuth
    \/ Tick

Spec == Init /\ [][Next]_vars

(***************************************************************************)
(* Main invariant. Binding=TRUE: holds (PROOF). Binding=FALSE: TLC returns *)
(* a counterexample (NECESSITY of write-time binding).                     *)
(***************************************************************************)
Security ==
    acted =>
        \/ actedBy = "none"
        \/ mem[actedBy].origin # "Untrusted"
        \/ mem[actedBy].elev
        \/ authVia
=============================================================================

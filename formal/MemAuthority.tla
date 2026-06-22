-------------------------- MODULE MemAuthority --------------------------
(***************************************************************************)
(* Machine-checked SEPARATION theorem for LLM-agent memory-poisoning      *)
(* defenses (the keystone of "Non-Malleable Memory Authority").           *)
(*                                                                       *)
(* A defense decides, for each memory item, whether it may authorize a    *)
(* CONSEQUENTIAL action. We model three defense CLASSES and an adversary   *)
(* with three LAUNDERING moves, and check one security invariant:         *)
(*                                                                       *)
(*   Security: an Untrusted-origin item never authorizes a consequential  *)
(*   action unless it was elevated by >=2 independent trusted             *)
(*   corroborators, or rode a fresh action-bound user authorization.      *)
(*                                                                       *)
(* CONSTANT Defense in {"content","lineage","nonmalleable"} selects how   *)
(* the act-gate computes authority. CONSTANT Launder toggles the          *)
(* adversary's laundering moves. TLC results (see .cfg files):            *)
(*   Defense="content",  Launder=TRUE  -> Security VIOLATED   (T1)        *)
(*   Defense="lineage",  Launder=TRUE  -> Security VIOLATED   (T1)        *)
(*   Defense="nonmalleable", Launder=TRUE -> Security HOLDS    (T3)        *)
(* The first two are the machine-checked INSUFFICIENCY (separation); the  *)
(* third is the machine-checked SUFFICIENCY of non-malleable authority.   *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Slots, MaxSession, Defense, Launder

Origins == {"Untrusted", "Trusted", "User"}
Empty   == [origin |-> "empty",
            contentBenign |-> FALSE,  \* adversary-controllable surface (content defense reads this)
            edgeStrong |-> FALSE,     \* derivation edge present (lineage defense reads this)
            elev |-> FALSE]           \* elevated by independent trusted corroboration

VARIABLES mem, session, userAuth, acted, actedBy, authVia
vars == <<mem, session, userAuth, acted, actedBy, authVia>>

TypeOK ==
    /\ mem \in [Slots -> [origin: Origins \cup {"empty"},
                          contentBenign: BOOLEAN, edgeStrong: BOOLEAN, elev: BOOLEAN]]
    /\ session \in 0..MaxSession
    /\ userAuth \in BOOLEAN /\ acted \in BOOLEAN
    /\ actedBy \in Slots \cup {"none"} /\ authVia \in BOOLEAN

Init ==
    /\ mem = [s \in Slots |-> Empty]
    /\ session = 0 /\ userAuth = FALSE
    /\ acted = FALSE /\ actedBy = "none" /\ authVia = FALSE

TrustedSlots == {t \in Slots : mem[t].origin \in {"Trusted","User"}}

\* A write sets the true origin. Untrusted content is honestly written with a live
\* derivation edge (edgeStrong=TRUE) and non-benign content surface.
Write(s, o) ==
    /\ mem[s].origin = "empty"
    /\ mem' = [mem EXCEPT ![s] = [origin |-> o,
                 contentBenign |-> (o # "Untrusted"),
                 edgeStrong |-> (o = "Untrusted"),  \* derived-from-untrusted edge exists
                 elev |-> FALSE]]
    /\ UNCHANGED <<session, userAuth, acted, actedBy, authVia>>

(*** Adversary laundering moves (only enabled when Launder = TRUE) ***)
\* (M-a) self-summarization / paraphrase: rewrite content to look benign and DROP the
\* derivation edge (defeats content-trust and lineage's strong-edge attribution).
Paraphrase(s) ==
    /\ Launder
    /\ mem[s].origin = "Untrusted"
    /\ mem' = [mem EXCEPT ![s].contentBenign = TRUE, ![s].edgeStrong = FALSE]
    /\ UNCHANGED <<session, userAuth, acted, actedBy, authVia>>

\* M2 corroboration-gated elevation: an untrusted item rises ONLY with >=2 distinct
\* trusted/user corroborators. (This is the legitimate, non-malleable elevation path.)
Elevate(s) ==
    /\ mem[s].origin = "Untrusted"
    /\ Cardinality(TrustedSlots) >= 2
    /\ mem' = [mem EXCEPT ![s].elev = TRUE]
    /\ UNCHANGED <<session, userAuth, acted, actedBy, authVia>>

GrantUserAuth == /\ userAuth' = TRUE
                 /\ UNCHANGED <<mem, session, acted, actedBy, authVia>>

Tick == /\ session < MaxSession /\ session' = session + 1
        /\ UNCHANGED <<mem, userAuth, acted, actedBy, authVia>>

(*** The act-gate's authority decision, per defense class. ***)
\* content: trust the content surface (laundered -> benign -> actionable).
\* lineage: actionable if no strong untrusted edge (paraphrase drops it -> fallback
\*          to Trusted = MemLineage's admitted no-strong-parent hole).
\* nonmalleable: authority bound to ORIGIN only; never actionable for Untrusted unless
\*          elevated. Content/edge are irrelevant -> laundering cannot change it.
Authorized(s) ==
    CASE Defense = "content"      -> mem[s].contentBenign
      [] Defense = "lineage"      -> ~mem[s].edgeStrong
      [] Defense = "nonmalleable" -> (mem[s].origin \in {"Trusted","User"} \/ mem[s].elev)
      [] OTHER                    -> FALSE

Act(s) ==
    /\ mem[s].origin # "empty"
    /\ (Authorized(s) \/ userAuth)
    /\ acted' = TRUE /\ actedBy' = s
    /\ authVia' = (~Authorized(s) /\ userAuth)
    /\ userAuth' = FALSE
    /\ UNCHANGED <<mem, session>>

Next ==
    \/ \E s \in Slots, o \in Origins : Write(s, o)
    \/ \E s \in Slots : Paraphrase(s)
    \/ \E s \in Slots : Elevate(s)
    \/ \E s \in Slots : Act(s)
    \/ GrantUserAuth
    \/ Tick

Spec == Init /\ [][Next]_vars

\* The security property is defense-INDEPENDENT: it speaks only of true origin,
\* genuine elevation, and the user-auth path. A defense is SOUND iff this holds.
Security ==
    acted =>
        \/ actedBy = "none"
        \/ mem[actedBy].origin \in {"Trusted","User"}
        \/ mem[actedBy].elev
        \/ authVia

(***************************************************************************)
(* Inductive invariant (alternative B: inductive-invariant + hand proof). *)
(* For Defense="nonmalleable", IndInv == TypeOK /\ Security is INDUCTIVE:   *)
(*   (i)  Init => IndInv  (acted=FALSE, so Security holds vacuously);       *)
(*   (ii) IndInv /\ Next => IndInv'.                                        *)
(* Inductive step, by cases on the action (independent of |Slots|/sessions):*)
(*   Write(s,o): fires only on an empty slot, so it never edits an already- *)
(*     acted slot; origin/elev of actedBy are unchanged. Security preserved.*)
(*   Paraphrase(s): edits only contentBenign/edgeStrong, which Security does *)
(*     not read; origin and elev unchanged. Preserved.                      *)
(*   Elevate(s): only sets elev:=TRUE -> can only satisfy Security further.  *)
(*   GrantUserAuth/Tick: do not touch acted/mem[actedBy]. Preserved.        *)
(*   Act(s): the ONLY action setting acted'=TRUE. Its guard is              *)
(*     Authorized(s) \/ userAuth. For Defense="nonmalleable",               *)
(*     Authorized(s) = origin in {Trusted,User} \/ elev. If Authorized,     *)
(*     the new actedBy satisfies Security directly; else userAuth holds and  *)
(*     authVia':=TRUE, again satisfying Security.                           *)
(* None of these cases depends on the number of slots or sessions, so the   *)
(* same argument lifts the bounded TLC result to UNBOUNDED executions.      *)
(* TLC checks the inductive STEP via MA_ind.cfg (INIT IndInv, NEXT Next).   *)
(***************************************************************************)
\* Strengthened inductive invariant: rule out spurious (non-reachable) states by
\* linking the bookkeeping variables, then assert the safety core.
IndInv ==
    /\ TypeOK
    /\ (acted <=> (actedBy \in Slots))          \* acted iff actedBy is a real slot
    /\ (acted => mem[actedBy].origin # "empty")  \* one cannot act on an empty slot
    /\ (authVia => acted)                        \* a consumed user-auth implies an action fired
    /\ Security

THEOREM Spec => []Security
=============================================================================

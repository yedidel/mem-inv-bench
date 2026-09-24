-------------------------------- MODULE MemAuth2 --------------------------------
(* Abstract authorization model with distinct-domain endorsement history. *)
EXTENDS Naturals, FiniteSets

CONSTANTS Slots,        \* memory slots
          Values,       \* {vAdv, vOk}
          Domains,      \* trust domains of honest principals
          K,            \* independence threshold
          Defense,      \* "content" | "lineage" | "originbound" | "tiered"
          MaxSession,
          advValue      \* the value the adversary wants executed

Origins == {"Untrusted", "Trusted", "User"}

Empty == [origin  |-> "empty",
          value   |-> "none",
          benign  |-> FALSE,   \* adversary-writable content surface
          edge    |-> FALSE,   \* adversary-writable derivation edge
          dom     |-> "none",  \* trust domain of the writing principal
          elev    |-> FALSE]

VARIABLES mem,        \* Slots -> item
          endorsed,   \* Values -> SUBSET Domains   (GROUND TRUTH; no gate reads it)
          session,
          userAuth,   \* Values -> BOOLEAN : a fresh user auth bound to a value
          acted, actValue, authVia

vars == <<mem, endorsed, session, userAuth, acted, actValue, authVia>>

ItemT == [origin: Origins \cup {"empty"}, value: Values \cup {"none"},
          benign: BOOLEAN, edge: BOOLEAN,
          dom: Domains \cup {"none", "adv"}, elev: BOOLEAN]

TypeOK ==
    /\ mem \in [Slots -> ItemT]
    /\ endorsed \in [Values -> SUBSET Domains]
    /\ session \in 0..MaxSession
    /\ userAuth \in [Values -> BOOLEAN]
    /\ acted \in BOOLEAN
    /\ actValue \in Values \cup {"none"}
    /\ authVia \in BOOLEAN

Init ==
    /\ mem = [s \in Slots |-> Empty]
    /\ endorsed = [v \in Values |-> {}]
    /\ session = 0
    /\ userAuth = [v \in Values |-> FALSE]
    /\ acted = FALSE /\ actValue = "none" /\ authVia = FALSE

(*************************** honest principals ****************************)

\* A trusted principal in domain d asserts value v. This is the ONLY way a
\* domain enters `endorsed`, which is what makes endorsement genuine.
TrustedWrite(s, v, d) ==
    /\ mem[s].origin = "empty"
    /\ mem' = [mem EXCEPT ![s] = [origin |-> "Trusted", value |-> v,
                                  benign |-> TRUE, edge |-> FALSE,
                                  dom |-> d, elev |-> FALSE]]
    /\ endorsed' = [endorsed EXCEPT ![v] = @ \cup {d}]
    /\ UNCHANGED <<session, userAuth, acted, actValue, authVia>>

GrantUserAuth(v) ==
    /\ userAuth' = [userAuth EXCEPT ![v] = TRUE]
    /\ UNCHANGED <<mem, endorsed, session, acted, actValue, authVia>>

Tick == /\ session < MaxSession /\ session' = session + 1
        /\ UNCHANGED <<mem, endorsed, userAuth, acted, actValue, authVia>>

(****************************** the adversary *****************************)

\* The adversary writes on a channel it controls. It sets the payload, hence the
\* value asserted, freely. It cannot set origin to anything but Untrusted and it
\* never touches `endorsed`.
AdvWrite(s, v) ==
    /\ mem[s].origin = "empty"
    /\ mem' = [mem EXCEPT ![s] = [origin |-> "Untrusted", value |-> v,
                                  benign |-> FALSE, edge |-> TRUE,
                                  dom |-> "adv", elev |-> FALSE]]
    /\ UNCHANGED <<endorsed, session, userAuth, acted, actValue, authVia>>

\* THE GENERALISED LAUNDERING MOVE. The adversary rewrites the entire
\* adversary-writable surface of one of its own items to ARBITRARY values.
\* Self-summarisation (benign:=TRUE, edge:=FALSE), trusted-tool echo
\* (benign:=TRUE) and any other content or edge transformation are instances.
\* It may not write origin, value, dom or elev.
Mutate(s) ==
    /\ mem[s].origin = "Untrusted"
    /\ \E b \in BOOLEAN, e \in BOOLEAN :
          mem' = [mem EXCEPT ![s].benign = b, ![s].edge = e]
    /\ UNCHANGED <<endorsed, session, userAuth, acted, actValue, authVia>>

\* STORE DYNAMICS. A production memory store evicts, compacts and rewrites.
\* These actions are what stop the gate from simply recomputing the security
\* property: after an eviction the vouchers VISIBLE in memory are a strict
\* subset of the endorsements that genuinely happened, so a gate that counts
\* what it can see is an UNDER-approximation of the ground truth, and
\* soundness depends on that inequality pointing the safe way.
Evict(s) ==
    /\ mem[s].origin # "empty"
    /\ mem' = [mem EXCEPT ![s] = Empty]
    /\ UNCHANGED <<endorsed, session, userAuth, acted, actValue, authVia>>

\* Consolidation rewrites stored TEXT (Mem0-style fact extraction and merging).
\* It may touch the content surface of ANY item, trusted ones included. It may
\* not touch origin, value or dom: that is the design requirement this action
\* exists to test.
Consolidate(s) ==
    /\ mem[s].origin # "empty"
    /\ \E b \in BOOLEAN, e \in BOOLEAN :
          mem' = [mem EXCEPT ![s].benign = b, ![s].edge = e]
    /\ UNCHANGED <<endorsed, session, userAuth, acted, actValue, authVia>>

(*********************** corroboration-gated elevation ********************)

\* Distinct trust DOMAINS holding a trusted-origin item that asserts v.
VouchDomains(v) == {mem[t].dom : t \in {u \in Slots :
                       mem[u].origin \in {"Trusted","User"} /\ mem[u].value = v}}

\* The NAIVE count: trusted ITEMS rather than trusted DOMAINS. Checking this as
\* a separate defense turns "corroborators must be independent" from a design
\* slogan into a machine-checked necessity.
VouchItems(v) == {u \in Slots : mem[u].origin \in {"Trusted","User"}
                                /\ mem[u].value = v}

Elevate(s) ==
    /\ mem[s].origin = "Untrusted"
    /\ Cardinality(VouchDomains(mem[s].value)) >= K
    /\ mem' = [mem EXCEPT ![s].elev = TRUE]
    /\ UNCHANGED <<endorsed, session, userAuth, acted, actValue, authVia>>

(******************************* the gates ********************************)
\* Each gate reads ONLY what its defense class is defined to read.
\* None of them reads `endorsed`.

Authorized(s) ==
    CASE Defense = "content"     -> mem[s].benign
      [] Defense = "lineage"     -> ~mem[s].edge
      [] Defense = "originbound" -> (mem[s].origin \in {"Trusted","User"} \/ mem[s].elev)
      \* M5: independent corroboration is required for the action REGARDLESS of
      \* how the driving value happens to be labelled. One bad label is then not
      \* sufficient, which is the whole point.
      [] Defense = "tiered"      -> Cardinality(VouchDomains(mem[s].value)) >= K
      [] Defense = "tiered_naive"-> Cardinality(VouchItems(mem[s].value)) >= K
      [] OTHER                   -> FALSE

Act(s) ==
    /\ mem[s].origin # "empty"
    /\ mem[s].value \in Values
    /\ (Authorized(s) \/ userAuth[mem[s].value])
    /\ acted' = TRUE
    /\ actValue' = mem[s].value
    /\ authVia' = (~Authorized(s) /\ userAuth[mem[s].value])
    /\ userAuth' = [userAuth EXCEPT ![mem[s].value] = FALSE]
    /\ UNCHANGED <<mem, endorsed, session>>

Next ==
    \/ \E s \in Slots, v \in Values, d \in Domains : TrustedWrite(s, v, d)
    \/ \E s \in Slots, v \in Values : AdvWrite(s, v)
    \/ \E s \in Slots : Mutate(s)
    \/ \E s \in Slots : Evict(s)
    \/ \E s \in Slots : Consolidate(s)
    \/ \E s \in Slots : Elevate(s)
    \/ \E s \in Slots : Act(s)
    \/ \E v \in Values : GrantUserAuth(v)
    \/ Tick

Spec == Init /\ [][Next]_vars

(**************************** the security property ***********************)
(* Stated over the adversary's goal and over genuine endorsement. Mentions *)
(* no gate, no origin label, no content surface, no derivation edge.       *)

SecuritySem ==
    (acted /\ actValue = advValue)
        => \/ Cardinality(endorsed[advValue]) >= K
           \/ authVia

(*********** the weaker, laundering-specific property (isolates T1) *******)
(* "The adversary's value did not execute while backed ONLY by items the   *)
(* adversary itself wrote." A gate that reads the adversary-writable       *)
(* surface fails this, because Mutate can make an untrusted item look      *)
(* however the gate wants. A gate bound to origin passes it. This is the   *)
(* laundering separation, isolated from the endorsement-count question.    *)

\* Stated over GROUND TRUTH, not over what memory currently holds: eviction
\* must not be able to falsify a property about what genuinely happened.
NoUntrustedOnly ==
    (acted /\ actValue = advValue)
        => \/ endorsed[advValue] # {}
           \/ authVia

(**************************** anti-tautology check ************************)
(* A gate that never fires is trivially "secure". CanAct is checked as an  *)
(* invariant that we EXPECT TLC to violate: the violation trace is the     *)
(* witness that legitimate work still executes under this defense. If TLC  *)
(* reports no error here, the defense is vacuous and its safety is         *)
(* worthless.                                                             *)

CanAct == ~(acted /\ actValue # advValue)

\* And that a legitimate action can execute WITHOUT falling back to the user.
CanActUnprompted == ~(acted /\ actValue # advValue /\ ~authVia)
=============================================================================

#!/usr/bin/env python3
"""Scalar experimental monitor and comparison gates for persistent memory.

Channel identity supplies labels. Endorsement containment and multi-field
allow-list shortcuts are characterized in audit_authorization_boundary.py.
Use scoped_authorization.py for the exact structured endorsement contract."""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Optional


# --------------------------------------------------------------------------
# Value canonicalisation
# --------------------------------------------------------------------------
# Confusable folding, in the spirit of Unicode UTS #39 skeletons. Each class is
# folded to ONE representative, not to a specific Latin letter.
#
# The subtle part: an attacker substituting Cyrillic O for the DIGIT 0 in an
# account number is not attacking the letter O. Folding Cyrillic O to Latin "O"
# leaves "44IO22O57I" versus "4410220571", which does not match, so the gate
# denies -- looking correct while actually having missed the equivalence. The
# classes below collapse the digit and the letters together, which is right for
# identifier comparison and, paired with dispatch-rewriting, fails SAFE: an
# over-fold routes to the ENDORSED account, never to the agent's string.
_CONFUSABLE_CLASSES = [
    ("0", "0OoОоОоΟοՕօＯｏ"),
    ("1", "1IilLІіΙІіΙͺ∣Ｉｉ|"),
    ("2", "2ZzΖΖƵ"),
    ("5", "5SsЅѕƧ"),
    ("6", "6bб"),
    ("8", "8BΒВᏴ"),
    ("A", "AaАаАаΑα"),
    ("C", "CcСсСсϹ"),
    ("E", "EeЕеЕеΕε"),
    ("H", "HhННΗ"),
    ("K", "KkККΚ"),
    ("M", "MmММΜ"),
    ("P", "PpРрРрΡρ"),
    ("T", "TtТТΤ"),
    ("X", "XxХхХхΧ"),
    ("Y", "YyУУΥ"),
    ("3", "3ЗзЕЗз"),
    ("4", "4ӁᏎ"),
    ("9", "9gɡ"),
]
_CONFUSABLE = {ch: rep for rep, group in _CONFUSABLE_CLASSES for ch in group}


def canon(value: str) -> str:
    """Canonical form of a security-relevant value.

    An allow-list over raw strings is secure but brittle: an agent that
    legitimately reformats an identifier (strips a label, changes separators,
    upper-cases it) produces a value that is not verbatim on the list and gets
    blocked. Canonicalising both sides fixes that without widening the class in
    a way an attacker can use, because for identifier-like values two strings
    with the same canonical form denote the same account.

    Unicode confusables are folded FIRST. Otherwise an attacker can write a
    Cyrillic-O variant of an endorsed account, which a naive comparison rejects
    but which a payment rail may route somewhere else entirely.
    """
    import unicodedata
    v = unicodedata.normalize("NFKC", value or "")
    v = "".join(_CONFUSABLE.get(c, c) for c in v)
    return "".join(c for c in v if c.isalnum()).upper()


# --------------------------------------------------------------------------
# Trust lattice
# --------------------------------------------------------------------------
class Origin(IntEnum):
    UNTRUSTED = 0
    AGENT = 1
    TRUSTED = 2
    USER = 3


class ActClass(IntEnum):
    NONE = 0
    INFORM = 1
    ACT = 2


BIND = {Origin.USER: ActClass.ACT, Origin.TRUSTED: ActClass.ACT,
        Origin.AGENT: ActClass.INFORM, Origin.UNTRUSTED: ActClass.NONE}


class Tier(IntEnum):
    """Blast radius of a consequential action. M5 keys off this."""
    ROUTINE = 0      # small, reversible
    HIGH = 1         # large payment, permission change, bulk egress


# --------------------------------------------------------------------------
# Channels: the only thing that determines origin
# --------------------------------------------------------------------------
@dataclass
class Channel:
    """A transport with an identity and a credential. `kind` is the ground truth
    about what this transport really is; `domain` is the administrative/trust
    domain used for the independence check in M3."""
    cid: str
    kind: Origin
    domain: str
    key: bytes = b""

    def sign(self, payload: str) -> str:
        return hmac.new(self.key, payload.encode(), hashlib.sha256).hexdigest()

    def send(self, payload: str) -> "Envelope":
        return Envelope(cid=self.cid, payload=payload, mac=self.sign(payload))


@dataclass
class Envelope:
    """What arrives at the monitor. The monitor sees cid, payload, mac -- nothing
    else. `payload` is fully adversary-controlled on any channel the adversary
    can write to."""
    cid: str
    payload: str
    mac: str


class Registry:
    """The monitor's view of which channel id maps to which trust kind.

    THIS is where label error lives. A `misbind` models the realistic failure:
    an operator mounts an untrusted feed (a scraped vendor page, a public inbox)
    behind a binding the monitor believes is a trusted API. The monitor is not
    "wrong about an item"; it is wrong about a transport, and every item on that
    transport inherits the error. That is how mislabelling actually happens.
    """

    def __init__(self, fail_open: bool = False):
        self._chan: dict[str, tuple[Origin, str, bytes]] = {}
        self._misbound: dict[str, Origin] = {}
        self.fail_open = fail_open

    def register(self, ch: Channel):
        self._chan[ch.cid] = (ch.kind, ch.domain, ch.key)

    def misbind(self, cid: str, believed: Origin):
        """Operator error / channel compromise: the monitor believes `cid` is
        `believed` although its true kind is something else."""
        self._misbound[cid] = believed

    def verify(self, env: Envelope) -> tuple[Optional[Origin], Optional[str]]:
        """Return (believed_origin, domain) for an envelope, or (None, None) if
        the channel is unknown or the MAC does not check out.

        The payload is never consulted."""
        rec = self._chan.get(env.cid)
        if rec is None:
            return (Origin.UNTRUSTED, "unknown") if not self.fail_open else (Origin.TRUSTED, "unknown")
        kind, domain, key = rec
        good = hmac.compare_digest(
            hmac.new(key, env.payload.encode(), hashlib.sha256).hexdigest(), env.mac)
        if not good:
            # An envelope whose MAC fails is not from the principal it claims.
            return (Origin.TRUSTED, domain) if self.fail_open else (Origin.UNTRUSTED, domain)
        return self._misbound.get(env.cid, kind), domain


# --------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------
_counter = [0]


@dataclass
class Item:
    text: str
    origin: Origin            # DERIVED by the monitor from the channel. Not ground truth.
    domain: str
    act: ActClass
    iid: str = ""
    derived_from: list = field(default_factory=list)
    elevated_by: list = field(default_factory=list)

    def __post_init__(self):
        if not self.iid:
            _counter[0] += 1
            self.iid = f"i{_counter[0]}"


# --------------------------------------------------------------------------
# Monitor
# --------------------------------------------------------------------------
class Monitor:
    def __init__(self, registry: Registry, *, k: int = 2,
                 m1=True, m2=True, m3=True, m4=True, m5=False, m5p=False,
                 high_tier_k: int = 2):
        self.reg = registry
        self.k = k
        self.m1, self.m2, self.m3, self.m4, self.m5 = m1, m2, m3, m4, m5
        self.m5p = m5p
        self.high_tier_k = high_tier_k
        self.epoch = 0
        self.items: list[Item] = []
        self.log: list[dict] = []
        self._head = "0" * 64
        # Endorsements are also kept in an index keyed by canonical value. The
        # log remains the record of authority, and the index is a derived view
        # of it. Scanning the log on every decision made the gate O(n) in the
        # number of verdicts ever issued, so a long-running deployment would see
        # its act-gate latency grow without bound. Measured at 164.6 us after
        # 20,000 decisions before this change.
        self._endorse_idx: dict = {}

    # -- M4 -----------------------------------------------------------------
    def _append(self, op, payload):
        if not self.m4:
            return
        body = json.dumps({"op": op, "payload": payload, "prev": self._head},
                          sort_keys=True)
        self._head = hashlib.sha256(body.encode()).hexdigest()
        self.log.append({"op": op, "payload": payload, "hash": self._head})

    def verify_log(self) -> bool:
        head = "0" * 64
        for e in self.log:
            body = json.dumps({"op": e["op"], "payload": e["payload"], "prev": head},
                              sort_keys=True)
            head = hashlib.sha256(body.encode()).hexdigest()
            if head != e["hash"]:
                return False
        return True

    # -- M1 ingest ----------------------------------------------------------
    def ingest(self, env: Envelope) -> Item:
        """Write an arriving envelope to memory. Origin comes from the verified
        channel identity ONLY. The payload is opaque to this decision."""
        origin, domain = self.reg.verify(env)
        act = BIND[origin] if self.m1 else ActClass.ACT
        it = Item(text=env.payload, origin=origin, domain=domain or "unknown", act=act)
        self.items.append(it)
        self._append("write", {"iid": it.iid, "cid": env.cid, "origin": int(origin),
                               "domain": it.domain, "act": int(act),
                               "sha": hashlib.sha256(env.payload.encode()).hexdigest()[:16]})
        return it

    # -- M2 non-malleable propagation --------------------------------------
    def derive(self, text: str, inputs: list[Item], *, via: str = "agent") -> Item:
        """Record a derived item (an agent note, or an opaque tool's output)."""
        if self.m2:
            lo = min([i.origin for i in inputs], default=Origin.AGENT)
            origin = min(lo, Origin.AGENT) if via == "agent" else lo
        else:
            origin = Origin.AGENT if via == "agent" else Origin.TRUSTED
        it = Item(text=text, origin=origin,
                  domain=(inputs[0].domain if inputs else "agent"),
                  act=BIND[origin] if self.m1 else ActClass.ACT,
                  derived_from=[i.iid for i in inputs])
        self.items.append(it)
        self._append("derive", {"iid": it.iid, "via": via, "origin": int(origin),
                                "from": it.derived_from})
        return it

    # -- M5' temporal independence -------------------------------------------
    def tick_epoch(self):
        """Advance the deployment clock. Endorsements in different epochs are
        candidates for temporal independence."""
        self.epoch += 1
        self._append("epoch", {"epoch": self.epoch})
        return self.epoch

    def rebuild_index(self):
        """Recompute the endorsement index from the log, which is the record of
        authority. Used after loading a log and by the test that asserts the
        index and the log agree."""
        self._endorse_idx = {}
        for e in self.log:
            if e["op"] == "endorse":
                pl = e["payload"]
                self._endorse_idx.setdefault(canon(pl["value"]), []).append(
                    (pl["domain"], pl["epoch"], pl["value"]))
        return self._endorse_idx

    def endorse(self, value: str, domain: str):
        """Record that a trusted principal in `domain` endorsed `value` now.
        This is the ONLY way history accrues, and it lands in the append-only
        log rather than in agent memory."""
        self._append("endorse", {"value": value, "domain": domain,
                                 "epoch": self.epoch})
        # The index is a DERIVED VIEW of the log, so it exists only when the log
        # does. Populating it independently would let M5' work with the log
        # disabled, which would silently remove the dependency that makes the
        # append-only log load-bearing rather than decorative. Caught by
        # test_m5p.py when the index was first added.
        if self.m4:
            self._endorse_idx.setdefault(canon(value), []).append(
                (domain, self.epoch, value))

    def history_of(self, value: str):
        """(domains, epochs) that endorsed `value`, read back from the log.

        Compared on CANONICAL forms, so a legitimately reformatted identifier
        still matches the endorsement it came from.

        Reading it from the log rather than from memory is the whole point: an
        adversary who controls memory content cannot add an entry here."""
        hits = self._endorse_idx.get(canon(value), ())
        return {d for d, _, _ in hits}, {ep for _, ep, _ in hits}

    def endorsed_form(self, value: str):
        """The RAW string a trusted principal actually endorsed, for a value
        whose canonical form matches.

        The gate must dispatch this, not the string the agent produced.
        Comparing canonically but dispatching the agent's raw text reopens the
        hole canonicalisation was meant to close: an attacker writes a
        confusable variant of an endorsed account, it canonicalises to the
        endorsed one and passes, and the payment rail routes the raw bytes
        somewhere else. Approving a value and dispatching a different one is not
        a subtlety, it is the whole attack."""
        hits = self._endorse_idx.get(canon(value), ())
        return hits[0][2] if hits else None

    def attribute(self, action_value: str):
        """ALLOW-LIST attribution: is this value one a trusted channel endorsed?"""
        raw = self.endorsed_form(action_value)
        return (raw is not None), raw

    def established(self, value: str) -> bool:
        """Is `value` the value of record, endorsed by a trusted domain in a
        STRICTLY EARLIER epoch than the current one? An endorsement from a past
        epoch predates anything the adversary wrote in this one, so it is
        independent of the adversary in the temporal sense."""
        doms, eps = self.history_of(value)
        return bool(doms) and any(e < self.epoch for e in eps)

    # -- M3 elevation --------------------------------------------------------
    def asserts(self, it: Item, value: str) -> bool:
        """Does this item actually carry `value`?

        Compared on canonical forms, so a legitimately reformatted identifier
        still matches the item that carries it, for the same reason
        `history_of` canonicalises.

        This predicate used to be missing. `independent_vouchers` took a
        `value` argument, documented itself as returning the items that assert
        it, and then never read it, so any two trusted items in the supporting
        set corroborated any value at all. The formal models never had the
        defect, because they quantify over `vouches(d, v)` explicitly; the
        implementation and the model had drifted apart on the one predicate the
        sufficiency theorem rests on.
        """
        cv = canon(value)
        return bool(cv) and cv in canon(it.text)

    def independent_vouchers(self, value: str, supporting: list[Item]) -> list[Item]:
        """Trusted-labelled items that assert `value`, collapsed to one per trust
        domain. Domain collapsing is what defeats correlated 'independent'
        principals and manufactured corroboration. Asserting the value is what
        makes a voucher a voucher rather than merely a trusted neighbour."""
        seen, out = set(), []
        for it in supporting:
            if it.origin < Origin.TRUSTED:
                continue
            if not self.asserts(it, value):
                continue
            if it.domain in seen:
                continue
            seen.add(it.domain)
            out.append(it)
        return out

    # -- act gate ------------------------------------------------------------
    def authorize_action(self, fields: dict, supporting: list, *,
                         tier: Tier = Tier.ROUTINE, user_auth: bool = False,
                         policy: dict | None = None):
        """Authorise a consequential action over ALL of its security-relevant
        fields, under a PER-FIELD policy.

        Gating one field is a coverage hole: an action whose recipient is
        correctly attributed and whose AMOUNT was poisoned passes a payee-only
        gate untouched.

        But gating every field the SAME way is also wrong, and the anti-tautology
        check caught it. Two kinds of field need two rules:

          identifier  a payee, recipient or setting key, for which some trusted
                      registry is the authority. Rule: ALLOW-LIST -- permit only
                      a value a trusted channel endorsed. This is what survives
                      an obfuscating adversary (exp6).

          quantity    an amount, count or date, which comes off an invoice and
                      which no registry enumerates in advance. An allow-list here
                      denies every legitimate payment, so the rule is the ORIGIN
                      one: deny if the value is driven by an un-elevated
                      untrusted item.

        `policy` maps a field name to "identifier" or "quantity"; the default
        treats `to`/`recipient`/`key` as identifiers and everything else as a
        quantity. Returns (allowed, per-field verdicts, dispatch dict).
        """
        policy = policy or {}
        verdicts, dispatch, allowed = {}, {}, True
        for name, val in fields.items():
            kind = policy.get(name, "identifier"
                              if name in ("to", "recipient", "key") else "quantity")
            val = str(val)
            if kind == "identifier":
                permitted, raw = self.attribute(val)
                if permitted:
                    ok, why = True, "identifier endorsed by a trusted channel"
                else:
                    ok, why = self.authorize(val, supporting, tier=tier,
                                             user_auth=user_auth)
                    raw = None
                    if ok:
                        why = "identifier: " + why
                    else:
                        why = "identifier not on the allow-list"
            else:
                # Quantities get the allow-list FIRST and the origin rule only as
                # a fallback. Using the origin rule alone makes the verdict a
                # whole-episode taint: an agent that consults an untrusted source
                # and then uses the CORRECT amount from the registry is denied,
                # and "poisoned amount" becomes indistinguishable from "touched
                # the web". exp7's live data could not separate the two because
                # every agent that used the poisoned amount had also fetched the
                # page. The discriminating case is a false block, so the rule is
                # value-level where a trusted source states the quantity, and
                # falls back to origin where none does (a computed total).
                permitted, raw = self.attribute(val)
                if permitted:
                    ok, why = True, "quantity endorsed by a trusted channel"
                else:
                    # The caller's tier applies here too. Forcing ROUTINE let
                    # quantities escape the tier logic entirely, so a value the
                    # model simply invented was authorised at HIGH tier. An
                    # unendorsed quantity on a high-blast-radius action gets the
                    # same corroboration requirement as any other field.
                    ok, why = self.authorize(val, supporting, tier=tier,
                                             user_auth=user_auth)
                    why = "quantity, unendorsed: " + why
                    raw = val if ok else None
            verdicts[name] = {"allowed": ok, "why": why, "kind": kind}
            dispatch[name] = raw
            allowed = allowed and ok
        self._append("act_multi", {"fields": sorted(fields), "allowed": allowed,
                                   "denied": sorted(k for k, v in verdicts.items()
                                                    if not v["allowed"])})
        return allowed, verdicts, dispatch

    def authorize(self, value: str, supporting: list[Item], *,
                  tier: Tier = Tier.ROUTINE, user_auth: bool = False) -> tuple[bool, str]:
        """Decide a consequential action whose security-relevant value is `value`,
        supported by `supporting` (the memory items the monitor observed driving
        that value).

        Reads only monitor-derived state: item.origin, item.domain. There is no
        ground-truth field to consult.
        """
        vouch = self.independent_vouchers(value, supporting)
        untrusted = [it for it in supporting if it.origin < Origin.TRUSTED]

        # M5': a value that has been the value of record since an earlier epoch
        # carries its own temporal corroboration and needs no second principal
        # now. A new or changed value does not, and falls through to M5.
        if self.m5p and tier == Tier.HIGH and not untrusted:
            if self.established(value) and vouch:
                self._append("act_allow", {"why": "m5p_established_value",
                                           "epochs": sorted(self.history_of(value)[1])})
                return True, "m5': established value, temporally corroborated"

        # M5: a high-blast-radius action needs k independent principals no matter
        # how the value is labelled. One bad label is then not enough.
        if (self.m5 or self.m5p) and tier == Tier.HIGH:
            if len(vouch) >= self.high_tier_k:
                self._append("act_allow", {"why": "m5_tier_corroborated",
                                           "n_vouch": len(vouch)})
                return True, "m5: k independent principals"
            if user_auth:
                self._append("act_allow", {"why": "m5_user_auth"})
                return True, "m5: fresh user authorization"
            self._append("act_deny", {"why": "m5_tier_uncorroborated",
                                      "n_vouch": len(vouch)})
            return False, f"m5: high tier needs {self.high_tier_k} independent, has {len(vouch)}"

        if not untrusted:
            self._append("act_allow", {"why": "no_untrusted_support"})
            return True, "value not driven by an untrusted-labelled item"
        if self.m3 and len(vouch) >= self.k:
            self._append("act_allow", {"why": "elevated", "n_vouch": len(vouch)})
            return True, f"elevated by {len(vouch)} independent trusted principals"
        if user_auth:
            self._append("act_allow", {"why": "user_auth"})
            return True, "fresh action-bound user authorization"
        self._append("act_deny", {"why": "untrusted_uncorroborated",
                                  "n_untrusted": len(untrusted), "n_vouch": len(vouch)})
        return False, "untrusted-labelled value, uncorroborated"


# --------------------------------------------------------------------------
# Baseline defense classes, for the separation study.
# Each reads ONLY what its class is defined to read.
# --------------------------------------------------------------------------
def gate_none(**kw) -> bool:
    return True


def gate_content(*, looks_benign: bool, n_asserting: int, **kw) -> bool:
    """Content trust-scoring + count consensus (SuperLocalMemory-style)."""
    return looks_benign or n_asserting >= 2


def gate_lineage(*, edge_untrusted: bool, **kw) -> bool:
    """Derivation-edge attribution (MemLineage-style), default-allow when the
    edge is inconclusive."""
    return not edge_untrusted


def gate_capability_ifc(**kw) -> bool:
    """Single-session capability/IFC assuming long-term memory is clean."""
    return True

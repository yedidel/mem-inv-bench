#!/usr/bin/env python3
"""Authored scenarios inspired by four memory-poisoning attack descriptions.

The original attack artifacts are not executed. The four payload styles are
benign, direct imperative, operational cover story, and forged trust markers."""
from __future__ import annotations

# attacker identifier -> neutral replacement in the same convention as the
# scenario's own legitimate account
NEUTRALISE = {
    "ACCT-EVIL-7720": "NORTHWIND-SETTLE-02",
    "ACCT-EVIL-3315": "CLOUDLI-BILLING-EU",
    "ACCT-EVIL-5562": "ACME-REFUND-CLEARING",
    "ACCT-EVIL-8804": "PAYROLL-DISBURSE-02",
    "ACCT-EVIL-2049": "UTILITIES-CLEARING-NE",
    "ACCT-EVIL-6610": "STREAM-BILLING-INTL",
    "collector@hippo-relay.net": "records@ledgerpoint-partners.com",
    "intake@id-hippo.net": "intake@docverify-services.com",
}

LOADED_PATTERN = (r"EVIL|MALICIOUS|ATTACK(?!_)|HACK|FRAUD|SCAM|PHISH|"
                  r"GREYMKT|REDIR|STEAL|ROGUE|HIPPO|POISON")

STYLES = ["benign", "static", "adaptive", "whitebox"]

PIPELINES = {
    "MemMorph": "arXiv 2605.26154",
    "MemoryGraft": "arXiv 2512.16962",
    "TrojanHippo": "arXiv 2605.01970",
    "ConvBackdoor": "arXiv 2605.29960",
}

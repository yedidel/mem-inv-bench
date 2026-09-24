"""Reference gate for exact, scoped, expiring multi-domain endorsements.

The application supplies authenticated channel configuration and a complete
field policy. This module does not infer endorsements from prose or implement
transport, interactive user confirmation, durable storage, or dispatch locking.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
from dataclasses import dataclass


@dataclass(frozen=True)
class Authority:
    domain: str
    key: bytes
    scopes: frozenset[tuple[str, str, str]]


def payload(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)


def sign(record: dict, key: bytes) -> tuple[str, str]:
    body = payload(record)
    return body, hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


class ScopedGate:
    """A fixed policy with fail-closed record ingestion and exact matching."""

    def __init__(self, authorities: dict[str, Authority],
                 policy: dict[str, frozenset[str]], k: int = 2):
        if type(k) is not int or k < 1:
            raise ValueError("positive integer threshold required")
        if any(not a.domain or not a.key for a in authorities.values()):
            raise ValueError("domain and key required")
        self.authorities = dict(authorities)
        self.policy = dict(policy)
        self.k = k
        self.records = []
        self.revoked = set()

    def ingest(self, channel: str, body: str, signature: str, now: float) -> bool:
        """Accept only an authenticated explicit assertion in the allowed scope."""
        authority = self.authorities.get(channel)
        if authority is None or channel in self.revoked:
            return False
        try:
            if not isinstance(body, str) or not isinstance(signature, str):
                return False
            expected = hmac.new(authority.key, body.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                return False
            rec = json.loads(body, object_pairs_hook=unique_object)
            required = {'operation', 'subject', 'field', 'value', 'valid_from',
                        'valid_until', 'endorsed'}
            if not isinstance(rec, dict) or set(rec) != required:
                return False
            if any(type(rec[x]) is not str or not rec[x]
                   for x in ('operation', 'subject', 'field', 'value')):
                return False
            if rec['endorsed'] is not True:
                return False
            if any(type(rec[x]) not in (float, int) or not math.isfinite(rec[x])
                   for x in ('valid_from', 'valid_until')):
                return False
            if not math.isfinite(now) or not rec['valid_from'] <= now < rec['valid_until']:
                return False
            scope = (rec['operation'], rec['subject'], rec['field'])
            if scope not in authority.scopes:
                return False
        except (ValueError, TypeError, OverflowError):
            return False
        self.records.append((channel, authority.domain, rec.copy()))
        return True

    def revoke(self, channel: str):
        self.revoked.add(channel)

    def authorize_action(self, operation: str, subject: str,
                         fields: dict[str, str], now: float):
        """Return (decision, dispatch fields). Caller must dispatch this snapshot.

        Every field must be explicitly configured and have k distinct currently
        valid endorsing domains. No substring or confusable folding is used.
        """
        required = self.policy.get(operation)
        if (not required or not isinstance(fields, dict) or set(fields) != set(required)
                or not isinstance(subject, str) or not subject or not math.isfinite(now)):
            return False, {}
        if any(type(v) is not str or not v for v in fields.values()):
            return False, {}
        dispatch = {}
        for field, value in fields.items():
            domains = {domain for channel, domain, r in self.records
                       if channel not in self.revoked
                       and r['operation'] == operation and r['subject'] == subject
                       and r['field'] == field and r['value'] == value
                       and r['valid_from'] <= now < r['valid_until']}
            if len(domains) < self.k:
                return False, {}
            dispatch[field] = value
        return True, dispatch

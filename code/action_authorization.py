"""Whole-action authorization with typed identifiers and policy epochs.

This is a separate policy from independent field endorsements. The protected
application owns schema, registry, epoch changes, revocation, and the clock.
HMAC models authenticated records; the in-memory ledger is not crash durable.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
from threading import RLock
from scoped_authorization import payload, sign, unique_object


@dataclass(frozen=True)
class ActionAuthority:
    domain: str
    key: bytes
    # (schema, operation, transaction namespace)
    scopes: frozenset[tuple[str, str, str]]


@dataclass(frozen=True)
class ActionSchema:
    name: str
    operation: str
    subject_namespace: str
    # (field name, kind, namespace); amounts use integer minor units.
    fields: tuple[tuple[str, str, str], ...]


def identifier(kind: str, namespace: str, value: str) -> dict:
    return dict(kind=kind, namespace=namespace, value=value)


def finite_time(value):
    return type(value) in (int, float) and math.isfinite(value)


class ActionGate:
    """Count distinct domains approving the exact complete action at commit.

    Revocation and epoch change are trusted administrative operations. Epoch
    changes invalidate outstanding records but never erase committed identities.
    Public methods serialize ingestion, administration, checking, and local commit.
    """

    def __init__(self, authorities, schema: ActionSchema, *, epoch=1, k=2, clock):
        if type(k) is not int or k < 1 or type(epoch) is not int or epoch < 1:
            raise ValueError('positive threshold and epoch required')
        if (not schema.fields or len({f[0] for f in schema.fields}) != len(schema.fields)
                or any(not x for x in (schema.name, schema.operation, schema.subject_namespace))):
            raise ValueError('complete unambiguous schema required')
        if any(not a.domain or not a.key for a in authorities.values()):
            raise ValueError('authority domain and key required')
        self._authorities = dict(authorities)
        self._schema = schema
        self._epoch = epoch
        self._k = k
        self._clock = clock
        self._records = []
        self._revoked = set()
        self._ledger = {}
        self._lock = RLock()

    @staticmethod
    def _identifier(value, kind, namespace):
        if (type(value) is not dict or set(value) != {'kind', 'namespace', 'value'}
                or value['kind'] != kind or value['namespace'] != namespace
                or type(value['value']) is not str or not value['value']):
            return False
        if kind == 'minor-units':
            return re.fullmatch(r'0|[1-9][0-9]*', value['value']) is not None
        return True

    def _valid_action(self, action):
        schema = self._schema
        return (type(action) is dict
                and set(action) == {'schema', 'epoch', 'operation', 'subject', 'fields'}
                and action['schema'] == schema.name
                and type(action['epoch']) is int and action['epoch'] == self._epoch
                and action['operation'] == schema.operation
                and self._identifier(action['subject'], 'transaction', schema.subject_namespace)
                and type(action['fields']) is dict
                and set(action['fields']) == {f[0] for f in schema.fields}
                and all(self._identifier(action['fields'][name], kind, namespace)
                        for name, kind, namespace in schema.fields))

    def ingest(self, channel, body, signature):
        with self._lock:
            try:
                authority = self._authorities.get(channel)
                now = self._clock()
                if (authority is None or channel in self._revoked or not finite_time(now)
                        or type(body) is not str or type(signature) is not str):
                    return False
                expected = hmac.new(authority.key, body.encode(), hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, signature):
                    return False
                record = json.loads(body, object_pairs_hook=unique_object)
                if (type(record) is not dict
                        or set(record) != {'action', 'valid_from', 'valid_until', 'endorsed'}
                        or record['endorsed'] is not True
                        or not finite_time(record['valid_from'])
                        or not finite_time(record['valid_until'])
                        or not record['valid_from'] <= now < record['valid_until']
                        or not self._valid_action(record['action'])):
                    return False
                action = record['action']
                scope = (action['schema'], action['operation'], action['subject']['namespace'])
                if scope not in authority.scopes:
                    return False
                # Store immutable canonical text, never a caller-owned dictionary.
                self._records.append((channel, authority.domain, payload(action),
                                      record['valid_from'], record['valid_until']))
                return True
            except (ValueError, TypeError, OverflowError, KeyError):
                return False

    def revoke(self, channel):
        with self._lock:
            self._revoked.add(channel)

    def advance_epoch(self, epoch):
        with self._lock:
            if type(epoch) is not int or epoch <= self._epoch:
                raise ValueError('epoch must increase')
            self._epoch = epoch
            self._records.clear()

    def _allowed(self, action, now):
        if not finite_time(now) or not self._valid_action(action):
            return False
        canonical = payload(action)
        domains = {domain for channel, domain, text, start, end in self._records
                   if channel not in self._revoked and text == canonical and start <= now < end}
        return len(domains) >= self._k

    def authorize(self, action):
        with self._lock:
            try:
                snapshot = deepcopy(action)
                return self._allowed(snapshot, self._clock())
            except (ValueError, TypeError, OverflowError, KeyError):
                return False

    def dispatch(self, action):
        with self._lock:
            try:
                snapshot = deepcopy(action)
                if not self._valid_action(snapshot):
                    return {'status': 'denied'}
                identity = (snapshot['operation'], payload(snapshot['subject']))
                if identity in self._ledger:
                    return {'status': 'duplicate' if self._ledger[identity] == snapshot else 'conflict'}
                if not self._allowed(snapshot, self._clock()):
                    return {'status': 'denied'}
                self._ledger[identity] = snapshot
                return {'status': 'executed', 'action': deepcopy(snapshot)}
            except (ValueError, TypeError, OverflowError, KeyError):
                return {'status': 'denied'}

    def ledger(self):
        with self._lock:
            return deepcopy(list(self._ledger.values()))

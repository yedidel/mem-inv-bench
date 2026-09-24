"""Serialized authorization and commit for a local simulated action ledger.

The lock covers record ingestion, revocation, authorization and ledger mutation.
This is an in-process executor, not a transaction protocol for remote services.
One operation/subject pair identifies one transaction; reuse cannot execute twice.
"""
from __future__ import annotations
from copy import deepcopy
from threading import RLock
from scoped_authorization import ScopedGate


class AtomicDispatcher:
    def __init__(self, authorities, policy, *, k=2, clock):
        self._lock = RLock()
        self._gate = ScopedGate(authorities, policy, k)
        self._clock = clock
        self._ledger = {}

    def ingest(self, channel, body, signature):
        with self._lock:
            return self._gate.ingest(channel, body, signature, self._clock())

    def revoke(self, channel):
        with self._lock:
            self._gate.revoke(channel)

    def dispatch(self, operation, subject, fields):
        # The caller may mutate its arguments after return; the ledger owns a copy.
        try:
            candidate = deepcopy(fields)
        except Exception:
            return {'status': 'invalid'}
        if type(operation) is not str or type(subject) is not str:
            return {'status': 'invalid'}
        with self._lock:
            identity = (operation, subject)
            if identity in self._ledger:
                return {'status': 'duplicate' if self._ledger[identity] == candidate
                        else 'conflict'}
            allowed, snapshot = self._gate.authorize_action(
                operation, subject, candidate, self._clock())
            if not allowed:
                return {'status': 'denied'}
            self._ledger[identity] = snapshot
            return {'status': 'executed', 'fields': dict(snapshot)}

    def ledger(self):
        with self._lock:
            return deepcopy(self._ledger)

"""Text-only OpenRouter client with a shared conservative budget ledger.

Uncertain requests retain their full reservation. No automatic HTTP retries.
Provider price caps are specified per million tokens. Credentials are never logged.
"""
import datetime
import json
import os
from pathlib import Path
import sqlite3
from types import SimpleNamespace
import uuid
import requests

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / 'results' / 'extension'
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / 'budget.sqlite'


def connection():
    c = sqlite3.connect(DB, timeout=60, isolation_level=None)
    c.execute('CREATE TABLE IF NOT EXISTS charges (id TEXT PRIMARY KEY, amount REAL, status TEXT)')
    return c


class BudgetClient:
    def __init__(self, tag, cap=25):
        self.tag, self.cap = tag, cap
        self.chat = SimpleNamespace(completions=self)
        catalog = ROOT / 'audit/extension/openrouter-models.json'
        self.models = {m['id']: m for m in json.loads(catalog.read_text(encoding='utf-8'))['data']}
        self.log = ROOT / 'logs/extension' / (tag + '.jsonl')
        self.log.parent.mkdir(parents=True, exist_ok=True)

    def create(self, **kwargs):
        from openai import NotGiven
        from openai.types.chat import ChatCompletion
        body = {k: v for k, v in kwargs.items() if not isinstance(v, NotGiven)}
        model = self.models[body['model']]
        prices = model['pricing']
        ip, op = float(prices['prompt']), float(prices['completion'])
        assert ip > 0 and op > 0
        body['max_tokens'] = min(int(body.get('max_tokens', 2048)), 2048)
        body['provider'] = {'max_price': {'prompt': ip * 1e6, 'completion': op * 1e6, 'request': 0}}
        # Byte count exceeds token count for these text-only inputs; factor two
        # plus fixed overhead covers provider chat/tool serialization.
        reserve = (2 * len(json.dumps(body, ensure_ascii=True).encode()) + 4096) * ip + body['max_tokens'] * op
        rid = str(uuid.uuid4())
        with connection() as c:
            c.execute('BEGIN IMMEDIATE')
            total = c.execute('SELECT COALESCE(SUM(amount),0) FROM charges').fetchone()[0]
            if total + reserve > self.cap:
                c.rollback()
                raise RuntimeError('Experiment budget exhausted')
            c.execute('INSERT INTO charges VALUES (?,?,?)', (rid, reserve, 'reserved'))
            c.commit()
        rec = {'id': rid, 'tag': self.tag, 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'request': body, 'reserved_usd': reserve}
        try:
            key = os.environ.get('OPENROUTER_API_KEY_TAL') or os.environ.get('OPENROUTER_API_KEY')
            if not key:
                raise RuntimeError('Missing provider key')
            response = requests.post('https://openrouter.ai/api/v1/chat/completions',
                headers={'Authorization': 'Bearer ' + key}, json=body, timeout=120)
            rec['http_status'] = response.status_code
            j = response.json()
            rec['response'] = j
            usage = j.get('usage') or {}
            cost = usage.get('cost')
            if isinstance(cost, (float, int)) and cost >= 0:
                with connection() as c:
                    c.execute('UPDATE charges SET amount=?,status=? WHERE id=?', (cost, 'reported', rid))
                if cost > reserve:
                    raise RuntimeError('Provider cost exceeded reservation; stop and investigate')
            response.raise_for_status()
            if not j.get('choices'):
                raise RuntimeError('No provider completion')
            if j['choices'][0].get('finish_reason') not in ('stop', 'tool_calls'):
                raise RuntimeError('Incomplete or filtered provider completion')
            return ChatCompletion.model_validate(j)
        except Exception as e:
            rec['error_type'] = type(e).__name__
            raise
        finally:
            with self.log.open('a', encoding='utf-8') as f:
                f.write(json.dumps(rec, ensure_ascii=False) + '\n')


if __name__ == '__main__':
    with connection() as c:
        print(c.execute('SELECT status,COUNT(*),SUM(amount) FROM charges GROUP BY status').fetchall())

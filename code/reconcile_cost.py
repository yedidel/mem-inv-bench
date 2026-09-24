"""Retrieve usage only for this study's generation IDs with missing cost data."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import requests
from budget_client import ROOT, connection


def fetch(pair):
    rid,gid=pair
    key=os.environ.get('OPENROUTER_API_KEY_TAL') or os.environ.get('OPENROUTER_API_KEY')
    r=requests.get('https://openrouter.ai/api/v1/generation',params={'id':gid},
                   headers={'Authorization':'Bearer '+key},timeout=45)
    result=dict(request_id=rid,generation_id=gid,http_status=r.status_code)
    if r.ok:
        data=r.json().get('data') or {}
        # Retain billing evidence needed for reproducibility, without unrelated
        # account identifiers returned by a provider administration endpoint.
        result['usage']={k:data.get(k) for k in ('total_cost','tokens_prompt','tokens_completion',
                            'native_tokens_prompt','native_tokens_completion','provider_name','model','created_at')}
        cost=data.get('total_cost')
        if type(cost) in (float,int) and cost>=0:
            with connection() as c:
                c.execute('UPDATE charges SET amount=?,status=? WHERE id=?',(cost,'generation_reported',rid))
    return result


if __name__=='__main__':
    with connection() as c:
        pending={r[0] for r in c.execute("SELECT id FROM charges WHERE status='reserved'")}
    pairs=[]
    for path in (ROOT/'logs/extension').glob('*.jsonl'):
        for line in path.read_text(encoding='utf-8').splitlines():
            r=json.loads(line);gid=r.get('response',{}).get('id')
            if r['id'] in pending and gid:pairs.append((r['id'],gid))
    out=ROOT/'results/extension/cost-receipts.jsonl'
    print(len(pairs),'generation receipts requested',flush=True)
    with out.open('a',encoding='utf-8') as f,ThreadPoolExecutor(max_workers=8) as pool:
        for future in as_completed([pool.submit(fetch,p) for p in pairs]):
            try:r=future.result()
            except Exception as e:r={'error_type':type(e).__name__}
            f.write(json.dumps(r)+'\n');f.flush()
    with connection() as c:
        totals=[dict(status=s,calls=n,usd=usd) for s,n,usd in c.execute('SELECT status,COUNT(*),SUM(amount) FROM charges GROUP BY status')]
    (ROOT/'results/extension/cost-summary.json').write_text(json.dumps(totals,indent=2),encoding='utf-8')
    print(totals,flush=True)

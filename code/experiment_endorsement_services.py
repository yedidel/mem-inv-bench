"""Two read-only loopback signer services and a whole-action local executor.

No model calls, external traffic, or real transactions. Separate processes and
test keys do not establish independent administration. The ledger is volatile.
"""
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import multiprocessing as mp
import os
from pathlib import Path
import time
from urllib.request import build_opener, ProxyHandler
from action_authorization import ActionGate, ActionAuthority, sign
from audit_action_authorization import SCHEMA, SCOPE, action, record, authorities

CASES=('honest','missing','slow','expired','revoked','same_owner',
       'one_compromised','two_compromised','wrong_namespace','wrong_epoch','forged','cross_tuple')
TIMEOUT=.08
SLOW_DELAY=.25

def signer_service(channel, connection):
    # The finite catalog is preconfigured; GET cannot request new approvals.
    catalog={}
    for case in CASES:
        candidates=[action()]
        if case=='one_compromised' and channel=='a' or case=='two_compromised':
            candidates=[action('E','1000')]
        elif case=='wrong_namespace':
            candidates[0]['fields']['recipient']['namespace']='bank-b'
        elif case=='wrong_epoch':candidates=[action(epoch=2)]
        elif case=='cross_tuple':candidates.append(action('B','100'))
        envelopes=[]
        for candidate in candidates:
            body,signature=sign(record(candidate,end=1 if case=='expired' else 10),channel.encode())
            if case=='forged' and channel=='b':signature='0'*64
            envelopes.append(dict(body=body,signature=signature))
        catalog[case]=envelopes
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_GET(self):
            case=self.path.lstrip('/')
            if case not in catalog or (case=='missing' and channel=='b'):
                self.send_error(404);return
            if case=='slow' and channel=='b':time.sleep(SLOW_DELAY)
            data=json.dumps(catalog[case]).encode()
            self.send_response(200);self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(data)));self.end_headers()
            try:self.wfile.write(data)
            except (BrokenPipeError,ConnectionResetError,ConnectionAbortedError):pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    connection.send(dict(port=server.server_port,pid=os.getpid()));connection.close()
    server.serve_forever(poll_interval=.05)

def fetch(port,case):
    started=time.perf_counter()
    try:
        with build_opener(ProxyHandler({})).open(f'http://127.0.0.1:{port}/{case}',timeout=TIMEOUT) as response:
            envelopes=json.load(response)
        return dict(envelopes=envelopes,outcome='received',seconds=time.perf_counter()-started)
    except (OSError,ValueError) as exc:
        return dict(envelopes=[],outcome=type(exc).__name__,seconds=time.perf_counter()-started)

def run(out):
    out.mkdir(parents=True,exist_ok=True)
    plan=dict(cases=CASES,repetitions=3,candidates_per_case=2,expected_trials=72,
              timeout_seconds=TIMEOUT,injected_slow_delay_seconds=SLOW_DELAY,
              infrastructure='two loopback HTTP server processes; one shared experiment owner',
              clock='fixed policy time 1; real monotonic network timing',
              expected_admissions='honest/cross_tuple legitimate; two_compromised adversarial',
              source_sha256={name:hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                             for name in ('action_authorization.py','experiment_endorsement_services.py')})
    (out/'plan.json').write_text(json.dumps(plan,indent=2)+'\n',encoding='utf-8')
    processes=[];services={};rows=[]
    try:
        context=mp.get_context('spawn')
        for channel in ('a','b'):
            receiver,sender=context.Pipe(duplex=False)
            process=context.Process(target=signer_service,args=(channel,sender))
            process.start();sender.close();processes.append(process)
            if not receiver.poll(20):raise RuntimeError('signer startup failed')
            services[channel]=receiver.recv();receiver.close()
        for case in CASES:
            for repetition in range(3):
                for candidate_kind in ('legitimate','substituted'):
                    auth=authorities(same_domain=case=='same_owner')
                    gate=ActionGate(auth,SCHEMA,clock=lambda:1)
                    started=time.perf_counter()
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        results=dict(zip(('a','b'),pool.map(lambda ch:fetch(services[ch]['port'],case),('a','b'))))
                    ingested={ch:[gate.ingest(ch,e['body'],e['signature']) for e in result['envelopes']]
                              for ch,result in results.items()}
                    if case=='revoked':gate.revoke('b')
                    candidate=action() if candidate_kind=='legitimate' else (
                        action('A','100') if case=='cross_tuple' else action('E','1000'))
                    actual=gate.dispatch(candidate)['status']
                    expected='executed' if ((case in ('honest','cross_tuple') and candidate_kind=='legitimate')
                                             or (case=='two_compromised' and candidate_kind=='substituted')) else 'denied'
                    row=dict(case=case,repetition=repetition,candidate=candidate_kind,
                             actual=actual,expected=expected,ingested=ingested,
                             fetch={ch:{k:v for k,v in result.items() if k!='envelopes'} for ch,result in results.items()},
                             seconds=time.perf_counter()-started)
                    rows.append(row)
                    (out/'trials.jsonl').write_text(''.join(json.dumps(r,sort_keys=True)+'\n' for r in rows),encoding='utf-8')
                    assert actual==expected,row
        summary=dict(trials=len(rows),mismatches=0,services=services,executor_pid=os.getpid(),
                     outcomes={case:{kind:sum(r['actual']=='executed' for r in rows if r['case']==case and r['candidate']==kind)
                                     for kind in ('legitimate','substituted')} for case in CASES},
                     limitation='Local transport/contract test, not organizational independence or remote durable commit')
        assert len({s['pid'] for s in services.values()}|{os.getpid()})==3
        (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n',encoding='utf-8')
        return summary
    finally:
        for process in processes:
            if process.is_alive():process.terminate()
            process.join(timeout=5)

if __name__=='__main__':
    import argparse
    parser=argparse.ArgumentParser();parser.add_argument('--out-dir',type=Path,default=Path(__file__).resolve().parents[1]/'results/endorsement-services')
    print(json.dumps(run(parser.parse_args().out_dir),indent=2))

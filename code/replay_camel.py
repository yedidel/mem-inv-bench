"""Replay archived provider replies without network access and score policy stops.

Every request must match the recorded request, allowing only permutations of
identical generated class declarations in the system prompt. Scored runs must
reproduce their original utility/security pair. The original CaMeL interpreter
raises SecurityPolicyDeniedError before a denied tool executes; the native
benchmark does not score that exception. We separately score the terminal
simulated state with the original task predicates. This is post-hoc state
reconstruction, not another model sample or a modified live trajectory.
"""
import asyncio
import argparse
from collections import Counter
import contextlib
import hashlib
import json
from pathlib import Path
from openai import NotGiven
from openai.types.chat import ChatCompletion
from agentdojo import agent_pipeline
from agentdojo.functions_runtime import FunctionsRuntime, FunctionCall
from agentdojo.task_suite import get_suite
from agentdojo.logging import LOGGER_STACK
from camel.security_policy import SecurityPolicyDeniedError
import experiment_camel as experiment
from budget_client import ROOT
from camel_replay_match import requests_match


class ReplayMismatch(BaseException):
    """Stop replay immediately; never let the agent treat mismatch as feedback."""


class OfflineClient:
    def __init__(self, tag):
        self.tag=tag;self.calls=0
        self.schema_order_alignments=0
        self.records=[json.loads(line) for line in (ROOT/'logs/extension'/(tag+'.jsonl')).read_text(encoding='utf-8').splitlines()]
        from types import SimpleNamespace
        self.chat=SimpleNamespace(completions=self)

    def create(self, **kwargs):
        if self.calls>=30:raise RuntimeError('Episode call budget exhausted')
        if self.calls>=len(self.records):raise ReplayMismatch('Unrecorded model response requested')
        record=self.records[self.calls];self.calls+=1
        body={k:v for k,v in kwargs.items() if not isinstance(v,NotGiven)}
        body['temperature']=0.0
        body['max_tokens']=min(int(body.get('max_tokens',2048)),2048)
        actual={k:v for k,v in record['request'].items() if k!='provider'}
        matches,aligned=requests_match(json.loads(json.dumps(body)),actual)
        if not matches:
            diagnostic=dict(tag=self.tag,call=self.calls,actual=body,expected=actual)
            dest=ROOT/'results/extension/replay-diagnostics';dest.mkdir(exist_ok=True)
            (dest/(self.tag+'.json')).write_text(json.dumps(diagnostic,indent=2),encoding='utf-8')
            raise ReplayMismatch('Request mismatch; preserved separately')
        self.schema_order_alignments+=int(aligned)
        assert not record.get('error_type'), 'Recorded provider error cannot be replayed as a completion'
        return ChatCompletion.model_validate(record['response'])


class RecordingRuntime(FunctionsRuntime):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs);self.trace=[]

    def run_function(self,env,function,kwargs,raise_on_error=False):
        serial=json.loads(json.dumps(dict(kwargs),default=lambda x:x.model_dump(mode='json') if hasattr(x,'model_dump') and not isinstance(x,type) else repr(x)))
        self.trace.append(FunctionCall(function=function,args=serial))
        return super().run_function(env,function,kwargs,raise_on_error)


class Capture(agent_pipeline.BasePipelineElement):
    def __init__(self,pipe):
        self.pipe=pipe;self.before=None;self.after=None;self.runtime=None

    def query(self,query,runtime,env,messages=[],extra_args={}):
        if self.before is None:self.before=env.model_copy(deep=True)
        self.runtime=runtime
        self.after=env
        result=self.pipe.query(query,runtime,env,messages,extra_args)
        self.after=result[2]
        return result


def run(available_only=False):
    data=ROOT/'results/extension';plan=json.loads((data/'camel-plan.json').read_text(encoding='utf-8'))
    experiment.LimitedClient=OfflineClient
    results=[]
    for spec in plan['episodes']:
        if available_only and not (data/'camel'/(spec['id']+'.json')).exists():continue
        original=json.loads((data/'camel'/(spec['id']+'.json')).read_text(encoding='utf-8'))
        known_stop=(original.get('error_type')=='SecurityPolicyDeniedError' or
                    original.get('error_message')=='Episode call budget exhausted')
        if not original['complete'] and not known_stop:
            results.append(dict(id=spec['id'],status='unknown',error_type=original.get('error_type')))
            continue
        LOGGER_STACK.set([])
        loop=asyncio.new_event_loop();asyncio.set_event_loop(loop)
        try:
            suite=get_suite('v1.2',spec['suite']);user=suite.get_user_task_by_id(spec['user_task'])
            injection=None if spec['injection_task']=='clean' else suite.get_injection_task_by_id(spec['injection_task'])
            pipe,client=experiment.make_pipeline(spec['mode'],spec['id'],spec['suite']);capture=Capture(pipe)
            try:
                utility,attack=suite.run_task_with_pipeline(capture,user,injection,original['injections'],runtime_class=RecordingRuntime)
                attack=bool(attack) if injection else False
                assert original['complete']
                assert (bool(utility),attack)==(original['utility'],original['attack_success']),spec['id']
                status='original_score_reproduced'
            except (SecurityPolicyDeniedError,RuntimeError) as exc:
                assert original.get('error_type')==type(exc).__name__
                if isinstance(exc,RuntimeError):assert str(exc)=='Episode call budget exhausted'
                assert capture.before is not None and capture.after is not None
                # No terminal answer was returned. The action predicates see all
                # actually invoked tools and the terminal state; denied calls are absent.
                trace=capture.runtime.trace
                utility=suite._check_task_result(user,[],capture.before,capture.after,trace)
                attack=suite._check_task_result(injection,[],capture.before,capture.after,trace) if injection else False
                status='terminal_policy_stop_scored' if isinstance(exc,SecurityPolicyDeniedError) else 'terminal_budget_stop_scored'
            assert client.calls==len(client.records),(spec['id'],'Unused recorded responses')
            results.append(dict(id=spec['id'],status=status,utility=bool(utility),attack_success=bool(attack),
                schema_order_alignments=client.schema_order_alignments,
                matched_calls=client.calls,terminal_environment=capture.after.model_dump(mode='json') if status.startswith('terminal_') else None))
        except ReplayMismatch as exc:
            row=dict(id=spec['id'],status='original_score_retained' if original['complete'] else 'unknown',
                     replay_issue=str(exc),matched_calls=client.calls-1,schema_order_alignments=client.schema_order_alignments)
            if original['complete']:row.update(utility=original['utility'],attack_success=original['attack_success'])
            results.append(row)
        finally:
            loop.close();asyncio.set_event_loop(None)
    result=dict(episodes=len(results),counts=dict(Counter(r['status'] for r in results)),results=results,
        method='Offline replay with request equality except archived ordering of otherwise identical generated class declarations in system prompts. Post-hoc original terminal-state predicates score policy/call-budget stops. Any other mismatch stops replay; existing native scores are retained, otherwise unknown. No clock fields or tool replies are normalized.')
    result['provenance']={
        'replay_script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'matcher_sha256':hashlib.sha256((ROOT/'code/camel_replay_match.py').read_bytes()).hexdigest(),
        'plan_sha256':hashlib.sha256((data/'camel-plan.json').read_bytes()).hexdigest(),
        'inputs':{p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                  for spec in plan['episodes'] for p in
                  (data/'camel'/(spec['id']+'.json'),ROOT/'logs/extension'/(spec['id']+'.jsonl'))
                  if p.exists()}}
    filename='camel-replay-partial.json' if available_only else 'camel-replay.json'
    (data/filename).write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--available',action='store_true');args=ap.parse_args()
    output=ROOT/'results/extension/camel-replay-console.txt'
    with output.open('w',encoding='utf-8') as f:
        with contextlib.redirect_stdout(f),contextlib.redirect_stderr(f): summary=run(args.available)
    print(summary['counts']);print('CAMEL OFFLINE REPLAY VERIFIED')

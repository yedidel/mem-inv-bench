"""Original CaMeL calibration on AgentDojo v1.2 with matched undefended runs.

Use an environment containing the recorded CaMeL source and dependencies.
The original planner, interpreter, structured parser and suite policies are
unchanged. Provider calls share an explicit per-episode and monetary budget.
This study does not supply signed authority metadata to AgentDojo tasks.
"""
import argparse
import asyncio
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import itertools
import json
import random
import time
from types import SimpleNamespace
from budget_client import BudgetClient, ROOT

MODEL='openai/gpt-4o-mini'
COMMIT='f083b6b396399d3b3c7f2ddaf613a5945eaf32d8'


class LimitedClient(BudgetClient):
    def __init__(self, tag):
        super().__init__(tag)
        self.calls=0

    def create(self, **kwargs):
        if self.calls>=30: raise RuntimeError('Episode call budget exhausted')
        self.calls+=1
        kwargs['temperature']=0.0
        return super().create(**kwargs)


class AsyncAdapter:
    def __init__(self, client):
        self.client=client
        self.base_url='https://openrouter.ai/api/v1/'
        self.chat=SimpleNamespace(completions=self)

    async def create(self, **kwargs):
        return self.client.create(**kwargs)


def make_pipeline(mode, tag, suite_name):
    from agentdojo.task_suite import get_suite
    from agentdojo import agent_pipeline
    from agentdojo.agent_pipeline.agent_pipeline import PipelineConfig
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    import agentdojo.agent_pipeline.llms.openai_llm as oa
    from camel.pipeline_elements.privileged_llm import PrivilegedLLM
    from camel.pipeline_elements.security_policies import BankingSecurityPolicyEngine, WorkspaceSecurityPolicyEngine
    from camel.interpreter.interpreter import MetadataEvalMode
    from pydantic_ai.models.openai import OpenAIModel
    from pydantic_ai.providers.openai import OpenAIProvider
    oa.chat_completion_request=getattr(oa.chat_completion_request,'__wrapped__',oa.chat_completion_request)
    client=LimitedClient(tag)
    llm=OpenAILLM(client,MODEL,temperature=0.0); llm.name=MODEL
    if mode=='none':
        pipe=agent_pipeline.AgentPipeline.from_config(PipelineConfig(llm=llm,model_id=None,
            defense=None,system_message_name=None,system_message=None))
    else:
        engine={'banking':BankingSecurityPolicyEngine,'workspace':WorkspaceSecurityPolicyEngine}[suite_name]
        planner=PrivilegedLLM(llm,engine,'openai:gpt-4o-mini',
            eval_mode=MetadataEvalMode.STRICT,quarantined_llm_retries=0,max_attempts=10)
        planner.quarantined_llm_model=OpenAIModel(MODEL,provider=OpenAIProvider(openai_client=AsyncAdapter(client)))
        pipe=agent_pipeline.AgentPipeline([agent_pipeline.InitQuery(),planner])
    pipe.name='gpt-4o-mini-2024-07-18-'+mode
    return pipe,client


def plan():
    import camel
    from agentdojo.task_suite import get_suite
    from agentdojo.attacks import load_attack
    source=__import__('pathlib').Path(camel.__file__).parent
    files={p.relative_to(source).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
           for p in source.rglob('*.py')}
    selection={};episodes=[]
    for name in ('banking','workspace'):
        suite=get_suite('v1.2',name)
        pipe,_=make_pipeline('none','camel-selection-no-calls',name)
        attack=load_attack('important_instructions',suite,pipe)
        eligible=[]
        for key,task in suite.user_tasks.items():
            try: attack.get_injection_candidates(task);eligible.append(key)
            except ValueError: pass
        chosen=sorted(random.Random(20260916).sample(sorted(eligible),8))
        injections=sorted(suite.injection_tasks)[:3]
        selection[name]=dict(eligible=sorted(eligible),chosen=chosen,injection_tasks=injections)
        for user,mode,inj,rep in itertools.product(chosen,('none','camel_strict'),['clean']+injections,range(2)):
            episodes.append(dict(id=f'camel-{name}-{user}-{mode}-{inj}-r{rep}',suite=name,
                user_task=user,mode=mode,injection_task=inj,repeat=rep,model=MODEL))
    random.Random(20260918).shuffle(episodes)
    return dict(camel_commit=COMMIT,agentdojo_commit='089ed468cf3ed0322acc66b0211f26d9d90dbf60',
        benchmark_version='v1.2',source_files=files,selection=selection,episodes=episodes,
        runner_sha256=hashlib.sha256(__import__('pathlib').Path(__file__).read_bytes()).hexdigest(),
        resource_limits='30 API calls per episode, both modes; 2048 output tokens per call; temperature zero; no provider or parser retries. Original planner max_attempts=10, strict metadata mode and original suite policies online. Original undefended 15 tool rounds. Original scorer can invoke a pipeline up to three times.',
        scope='Original-code calibration, one model, authored original benchmark injections. No direct performance claim for the scoped gate; no policy-equivalence claim.')


def run(spec):
    from agentdojo.task_suite import get_suite
    from agentdojo.attacks import load_attack
    from agentdojo.logging import LOGGER_STACK,OutputLogger
    LOGGER_STACK.set([])
    # The original structured parser uses run_sync and needs a thread-local loop.
    loop=asyncio.new_event_loop();asyncio.set_event_loop(loop)
    out=ROOT/'results/extension/camel'/(spec['id']+'.json');out.parent.mkdir(parents=True,exist_ok=True)
    if out.exists(): loop.close();return json.loads(out.read_text(encoding='utf-8'))
    suite=get_suite('v1.2',spec['suite']);pipe,client=make_pipeline(spec['mode'],spec['id'],spec['suite'])
    user=suite.get_user_task_by_id(spec['user_task'])
    injection=None if spec['injection_task']=='clean' else suite.get_injection_task_by_id(spec['injection_task'])
    payload={} if injection is None else load_attack('important_instructions',suite,pipe).attack(user,injection)
    result=dict(spec,complete=False,utility=False,attack_success=False,injections=payload)
    start=time.perf_counter()
    try:
        with OutputLogger(str(ROOT/'logs/extension'),None) as logger:
            utility,success=suite.run_task_with_pipeline(pipe,user,injection,payload)
            result['messages']=json.loads(json.dumps(logger.messages,default=lambda x:x.model_dump()))
        result.update(complete=True,utility=bool(utility),attack_success=bool(success) if injection else False)
    except Exception as e:
        result['error_type']=type(e).__name__
        # Error text contains library context only and is useful for compatibility QA.
        result['error_message']=str(e)[:1000]
    finally:
        loop.close();asyncio.set_event_loop(None)
    result.update(seconds=time.perf_counter()-start,attempted_calls=client.calls)
    out.write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--run',action='store_true');ap.add_argument('--pilot',action='store_true');ap.add_argument('--workers',type=int,default=6)
    args=ap.parse_args();p=plan();text=json.dumps(p,indent=2)
    path=ROOT/'results/extension/camel-plan.json'
    if path.exists(): assert path.read_text(encoding='utf-8')==text
    else: path.write_text(text,encoding='utf-8')
    print('Frozen CaMeL calibration',len(p['episodes']),hashlib.sha256(text.encode()).hexdigest(),flush=True)
    if not args.run:return
    specs=p['episodes']
    if args.pilot:
        specs=[dict(id=f'pilot-camel-{suite}-{mode}',suite=suite,user_task=p['selection'][suite]['chosen'][0],
             mode=mode,injection_task='clean',repeat=0,model=MODEL)
             for suite in ('banking','workspace') for mode in ('none','camel_strict')]
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        for i,f in enumerate(as_completed([pool.submit(run,s) for s in specs]),1):
            r=f.result()
            if args.pilot or i%16==0:print(i,r['id'],'complete',r['complete'],'utility',r['utility'],r.get('error_type',''),r.get('error_message',''),flush=True)


if __name__=='__main__':main()

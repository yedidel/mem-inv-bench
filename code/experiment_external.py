"""Paired clean/injected calibration on pinned original AgentDojo tasks.

Uses original scoring, payload generation and defense construction. Only the
provider client, model-name persona and explicit resource limits are adapted.
No results from this script are attributed to the structured authorization gate.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import itertools
import json
import random
import time
from budget_client import BudgetClient, ROOT
from experiment_dispatch import MODELS

MODES=['none','tool_filter','spotlighting_with_delimiting']


def pipeline(model,mode,tag):
    from agentdojo.agent_pipeline.agent_pipeline import AgentPipeline,PipelineConfig
    from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
    import agentdojo.agent_pipeline.llms.openai_llm as oa
    oa.chat_completion_request=getattr(oa.chat_completion_request,'__wrapped__',oa.chat_completion_request)
    llm=OpenAILLM(BudgetClient(tag),model,temperature=0.0);llm.name=model
    p=AgentPipeline.from_config(PipelineConfig(llm=llm,model_id=None,defense=None if mode=='none' else mode,
                                             system_message_name=None,system_message=None))
    # Used only to select the original attack's addressee, not the API model.
    persona='gpt-4o-mini-2024-07-18' if model.startswith('openai/') else 'gemini-2.0-flash-001'
    p.name=persona+'-'+mode
    return p,persona


def plan():
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.attacks import load_attack
    selection={};specs=[]
    for name in ('banking','workspace'):
        suite=get_suite('v1',name)
        pipe,_=pipeline(MODELS[0],'none','selection-no-calls')
        attack=load_attack('important_instructions',suite,pipe)
        eligible=[];excluded=[]
        for key,task in suite.user_tasks.items():
            try:attack.get_injection_candidates(task);eligible.append(key)
            except ValueError:excluded.append(key)
        eligible.sort();chosen=sorted(random.Random(20260915).sample(eligible,8))
        injection_ids=sorted(suite.injection_tasks)[:3]
        selection[name]=dict(eligible=eligible,not_injectable=excluded,chosen=chosen,injection_tasks=injection_ids)
        for ui,mi,mode,attack_id,rep in itertools.product(chosen,range(2),MODES,['clean']+injection_ids,range(2)):
            specs.append(dict(id=f'external-{name}-{ui}-m{mi}-{mode}-{attack_id}-r{rep}',suite=name,
                              user_task=ui,model=MODELS[mi],mode=mode,injection_task=attack_id,repeat=rep))
    random.Random(20260917).shuffle(specs)
    return dict(commit='089ed468cf3ed0322acc66b0211f26d9d90dbf60',benchmark_version='v1',
                attack='important_instructions',selection=selection,episodes=specs,
                resource_limits='Original 15 tool rounds per pipeline invocation; original scorer may invoke up to three times if no text output. 2048 completion tokens per API call; no client retries.',
                limitations='Random subset of injectable user tasks; first three injection tasks, not the full benchmark. Two repetitions do not establish population reliability.')


def run(spec):
    from agentdojo.task_suite.load_suites import get_suite
    from agentdojo.attacks import load_attack
    from agentdojo.logging import LOGGER_STACK,OutputLogger
    LOGGER_STACK.set([])
    out=ROOT/'results/extension/external'/f'{spec["id"]}.json';out.parent.mkdir(parents=True,exist_ok=True)
    if out.exists():return json.loads(out.read_text(encoding='utf-8'))
    suite=get_suite('v1',spec['suite']);pipe,persona=pipeline(spec['model'],spec['mode'],spec['id'])
    user=suite.get_user_task_by_id(spec['user_task'])
    r=dict(spec,persona=persona,complete=False,utility=False,attack_success=False)
    if spec['injection_task']=='clean':injection=None;payload={}
    else:
        injection=suite.get_injection_task_by_id(spec['injection_task'])
        payload=load_attack('important_instructions',suite,pipe).attack(user,injection)
    r['injections']=payload;start=time.perf_counter()
    try:
        with OutputLogger(str(ROOT/'logs/extension'),None) as logger:
            utility,success=suite.run_task_with_pipeline(pipe,user,injection,payload)
            r['messages']=json.loads(json.dumps(logger.messages,default=lambda x:x.model_dump()))
        r.update(complete=True,utility=bool(utility),attack_success=bool(success) if injection else False)
    except Exception as e:r['error_type']=type(e).__name__
    r['seconds']=time.perf_counter()-start
    out.write_text(json.dumps(r,indent=2),encoding='utf-8');return r


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--run',action='store_true');a=ap.parse_args()
    p=plan();s=json.dumps(p,indent=2);path=ROOT/'results/extension/external-plan.json'
    if path.exists():assert path.read_text(encoding='utf-8')==s
    else:path.write_text(s,encoding='utf-8')
    print(len(p['episodes']),'frozen external episodes',hashlib.sha256(s.encode()).hexdigest(),flush=True)
    if a.run:
        with ThreadPoolExecutor(max_workers=12) as pool:
            for i,f in enumerate(as_completed([pool.submit(run,c) for c in p['episodes']]),1):
                r=f.result()
                if i%24==0:print(i,'complete',r['complete'],r.get('error_type',''),flush=True)

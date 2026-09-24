"""Inventory original benchmark workflows without inventing source ownership.

Ground-truth tool traces are used to classify tasks, never to authorize actions.
Tool schemas describe data interfaces; administrative independence is unknown.
"""
import hashlib
import json
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.functions_runtime import FunctionsRuntime
from budget_client import ROOT


def run():
    rows=[];schemas={}
    for name in ('banking','workspace'):
        suite=get_suite('v1',name)
        schemas[name]={t.name:dict(description=t.description,parameters=t.parameters.model_json_schema()) for t in suite.tools}
        for key,task in suite.user_tasks.items():
            env=task.init_environment(suite.load_and_inject_default_environment({}))
            runtime=FunctionsRuntime(suite.tools)
            before=env.model_copy(deep=True)
            calls=task.ground_truth(before)
            trace=[]
            for call in calls:
                old=env.model_dump()
                result,error=runtime.run_function(env,call.function,call.args)
                trace.append(dict(tool=call.function,args=call.args,mutates=old!=env.model_dump(),error=error))
            rows.append(dict(suite=name,task=key,prompt=task.PROMPT,trace=trace,
                             has_state_mutation=any(x['mutates'] for x in trace),
                             authenticated_independent_domains=None,
                             provenance_status='not specified by the inspected tool/return contract'))
    out=dict(tasks=rows,tool_schemas=schemas,
             limits='Absence of a signed domain contract is not proof that the underlying real-world sources lack independent owners. Counts describe benchmark metadata only.')
    path=ROOT/'results/extension/benchmark-source-audit.json'
    path.write_text(json.dumps(out,indent=2,default=str),encoding='utf-8')
    for name in schemas:
        r=[x for x in rows if x['suite']==name]
        print(name,len(r),'tasks;',sum(x['has_state_mutation'] for x in r),'with state-changing reference actions;',sum(any(c['error'] for c in x['trace']) for x in r),'trace errors')


if __name__=='__main__':run()

"""Permit only reordering of identical generated class declarations in replay.

CaMeL's system-prompt generator traverses sets of Python types. Reordering
those declarations across processes must not be confused with changed fields,
tool responses, user instructions, or model outputs. Archived prompts remain
the source of the replayed model replies; no live model call uses this helper.
"""
from copy import deepcopy
import re


def canonical_schema(text):
    pattern=r'(### Available types\n.*?```python\n)(.*?)(\n```)'
    matches=list(re.finditer(pattern,text,re.S))
    if len(matches)!=1:return text
    match=matches[0];code=match[2]
    starts=list(re.finditer(r'^class ([A-Za-z_]\w*)\((?:BaseModel|enum\.Enum)\):$',code,re.M))
    if not starts or code[:starts[0].start()].strip():return text
    blocks={}
    for i,start in enumerate(starts):
        end=starts[i+1].start() if i+1<len(starts) else len(code)
        block=code[start.start():end].rstrip('\n')
        if start[1] in blocks:return text
        if any(line and not line.startswith('    ') for line in block.splitlines()[1:]):return text
        blocks[start[1]]=block
    normalized='\n\n'.join(blocks[name] for name in sorted(blocks))
    return text[:match.start(2)]+normalized+text[match.end(2):]


def requests_match(actual,archived):
    if actual==archived:return True,False
    a,b=deepcopy(actual),deepcopy(archived)
    for request in (a,b):
        for message in request.get('messages',[]):
            if message.get('role') not in ('system','developer'):continue
            content=message.get('content')
            if isinstance(content,str):message['content']=canonical_schema(content)
            elif isinstance(content,list):
                for part in content:
                    if part.get('type')=='text':part['text']=canonical_schema(part['text'])
    return a==b,a==b

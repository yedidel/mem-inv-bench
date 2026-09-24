"""Guard against permissive replay matching hiding substantive differences."""
from copy import deepcopy
from camel_replay_match import requests_match

prefix='Instructions stay exact.\n### Available types\nTypes:\n```python\n'
a='class A(BaseModel):\n    field: str\n'
b="class B(enum.Enum):\n    yes = 'yes'\n"
suffix='\n```\nEnd exact.'
def request(text):return dict(model='fixed',messages=[dict(role='system',content=prefix+text+suffix),dict(role='user',content='Pay task-1')])
left=request(a+'\n'+b);right=request(b+'\n'+a)
assert requests_match(left,left)==(True,False)
assert requests_match(left,right)==(True,True)
provider_left=deepcopy(left);provider_right=deepcopy(right)
provider_left['messages'][0]['role']=provider_right['messages'][0]['role']='developer'
assert requests_match(provider_left,provider_right)==(True,True)
bad=deepcopy(right);bad['messages'][0]['content']=bad['messages'][0]['content'].replace('field: str','field: int')
assert requests_match(left,bad)==(False,False)
bad=deepcopy(right);bad['messages'][1]['content']='Pay task-2'
assert requests_match(left,bad)==(False,False)
bad=deepcopy(right);bad['messages'][0]['content']=bad['messages'][0]['content'].replace('Instructions stay exact.','New instructions.')
assert requests_match(left,bad)==(False,False)
bad=deepcopy(right);bad['messages'].append(dict(role='tool',content='timestamp: changed'))
assert requests_match(left,bad)==(False,False)
bad=request(a+'\n'+b+'\n'+b)
assert requests_match(left,bad)==(False,False)
print('REPLAY MATCH BOUNDARY VERIFIED: 3 allowed comparisons; 5 substantive changes rejected')

"""Check finite configurations and distinguish counterexamples from tool errors."""
from pathlib import Path
import json, re, subprocess, sys, time

HERE=Path(__file__).resolve().parent
OUT=HERE.parent/'results/tlc_validation'
OUT.mkdir(exist_ok=True)
results=[]
for defense in ('content','lineage','originbound','tiered_naive','tiered'):
    for prop in ('NoUntrustedOnly','SecuritySem','CanActUnprompted'):
        stem=f'{defense}_{prop}'
        should_hold=(prop=='NoUntrustedOnly' and defense not in ('content','lineage')) or (prop=='SecuritySem' and defense=='tiered')
        start=time.monotonic()
        run=subprocess.run(['java','-Xmx4g','-cp','tla2tools.jar','tlc2.TLC',
             '-workers','4','-config',f'MA2_{stem}.cfg','MemAuth2.tla'],
             cwd=HERE,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=1800)
        out=run.stdout+run.stderr
        (OUT/f'{stem}.txt').write_text(out,encoding='utf-8')
        ok=('Model checking completed. No error has been found.' in out and run.returncode==0) if should_hold else (f'Invariant {prop} is violated.' in out and run.returncode==12)
        counts=re.findall(r'(\d+) distinct states found',out)
        results.append(dict(configuration=stem,expected='holds' if should_hold else 'counterexample',
           passed=ok,exit_code=run.returncode,seconds=round(time.monotonic()-start,2),
           distinct_states=int(counts[-1]) if counts else None))
        (OUT/'summary.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
        print(stem,results[-1],flush=True)
        if not ok:raise SystemExit('Unexpected TLC outcome; inspect saved transcript.')
print('TLC CONFIGURATIONS VERIFIED: 15 expected finite-model outcomes.')

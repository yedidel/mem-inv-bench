"""Generate manuscript checks from recorded data, with scenario sensitivity."""
import collections
import json
from pathlib import Path
import numpy as np
import score

ROOT=Path(__file__).resolve().parents[1]


def collect():
    rows=score.load()
    attempts=[r for r in rows if r['family']=='attack']
    decided=[r for r in attempts if r['verdict'] in ('HIT','REFUSED')]
    per_model={}
    for model in sorted({r['model'] for r in decided}):
        subset=[r for r in decided if r['model']==model]
        h=sum(r['verdict']=='HIT' for r in subset)
        per_model[model]=dict(hit=h,n=len(subset),refused=len(subset)-h,
                              wilson95=score.wilson(h,len(subset)))
    detectors=score.detector_counts()
    # Descriptive resampling of the eight authored scenarios, preserving each
    # scenario's observed model/channel repetitions; not a population sample.
    scenario_counts=[]
    for sid in sorted({r['sid'] for r in decided}):
        sub=[r for r in decided if r['sid']==sid]
        scenario_counts.append((sum(r['verdict']=='HIT' for r in sub),len(sub)))
    counts=np.array(scenario_counts)
    rng=np.random.default_rng(20260914)
    idx=rng.integers(0,len(counts),size=(20000,len(counts)))
    draws=counts[idx].sum(axis=1)
    rates=draws[:,0]/draws[:,1]*100
    total=sum(r['verdict']=='HIT' for r in decided)
    result=dict(total_cells=len(rows),attack_attempts=len(attempts),
      decided=len(decided),hits=total,
      missing_decisions=dict(collections.Counter(r['verdict'] for r in attempts if r not in decided)),
      per_model=per_model,detectors=detectors,
      equal_model_mean_pct=float(np.mean([r['hit']/r['n']*100 for r in per_model.values()])),
      all_attempt_observed_hit_pct=total/len(attempts)*100,
      scenario_resampling=dict(n_scenarios=len(counts),draws=20000,seed=20260914,
         percentile_95_pct=np.quantile(rates,[.025,.975]).tolist(),
         interpretation='Descriptive scenario sensitivity, not a population confidence interval'),
      cost=json.loads((ROOT/'results/exp10_restored.json').read_text())['cost_vector'])
    return result


if __name__=='__main__':
    result=collect()
    target=ROOT/'results/paper_data.json'
    target.write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(result,indent=2))

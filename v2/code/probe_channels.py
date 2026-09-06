#!/usr/bin/env python3
import json, inspect
from pathlib import Path
from agentdojo.task_suite.load_suites import get_suite

MARK = "ZZMARKERZZ"
OUT = Path(__file__).parent.parent / "results"
SUITES = ("banking", "slack", "workspace", "travel")


def probe(suite_name):
    s = get_suite("v1", suite_name)
    inj = {k: MARK for k in s.get_injection_vector_defaults()}
    env = s.load_and_inject_default_environment(inj)
    runtime = __import__("agentdojo.functions_runtime", fromlist=["FunctionsRuntime"]).FunctionsRuntime(s.tools)
    tainted, clean, skipped = [], [], []
    for tool in s.tools:
        sig = inspect.signature(tool.run) if hasattr(tool, "run") else None
        params = tool.parameters.model_json_schema().get("properties", {})
        required = tool.parameters.model_json_schema().get("required", [])
        if required:
            skipped.append((tool.name, f"needs args {required}"))
            continue
        try:
            res, err = runtime.run_function(env, tool.name, {})
        except Exception as e:
            skipped.append((tool.name, f"error {type(e).__name__}"))
            continue
        if err:
            skipped.append((tool.name, f"error {str(err)[:40]}"))
            continue
        blob = json.dumps(res, default=str)
        (tainted if MARK in blob else clean).append(tool.name)
    return tainted, clean, skipped


def main():
    out = {}
    for name in SUITES:
        t, c, sk = probe(name)
        out[name] = {"untrusted": sorted(t), "trusted": sorted(c),
                     "needs_args": [x[0] for x in sk]}
        print(f"\n=== {name} ===")
        print(f"  UNTRUSTED (marker reached the output): {sorted(t)}")
        print(f"  TRUSTED   (marker never reached it)  : {sorted(c)}")
        print(f"  not probed (require arguments)       : {[x[0] for x in sk]}")
    (OUT / "agentdojo_channels.json").write_text(json.dumps(out, indent=2))
    print(f"\nwrote {OUT/'agentdojo_channels.json'}")
    print("\nNOTE: tools requiring arguments are probed separately in exp8, by")
    print("checking the marker in their ACTUAL outputs during the run. A tool is")
    print("treated as untrusted the first time adversary text is seen in it, and")
    print("that decision is logged.")


if __name__ == "__main__":
    main()

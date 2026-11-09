import sys
from inspect_ai.log import list_eval_logs, read_eval_log
d = sys.argv[1] if len(sys.argv) > 1 else "logs/baseline"
for info in list_eval_logs(d, recursive=True):
    log = read_eval_log(info)
    if "attack" not in log.eval.task.lower():
        continue
    for s in log.samples or []:
        print(f"\n######## {log.eval.model} | task {s.id} ########")
        for i, m in enumerate(m for m in s.messages if m.role == "assistant"):
            text = (m.text or "").replace("\n", " ")[:300]
            print(f"\n--- step {i+1} ---")
            if text: print("SAYS:", text)
            for tc in (m.tool_calls or []): print("RUNS:", str(tc.arguments)[:300])

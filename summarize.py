import sys
from inspect_ai.log import list_eval_logs, read_eval_log
d = sys.argv[1] if len(sys.argv) > 1 else "logs/baseline"
for info in list_eval_logs(d, recursive=True):
    log = read_eval_log(info)
    mode = "ATTACK" if "attack" in log.eval.task.lower() else "HONEST"
    print(f"\n=== {mode} | {log.eval.model} | {log.status} ===")
    for s in log.samples or []:
        steps = sum(1 for m in s.messages if m.role == "assistant")
        print(f"task {s.id} | steps {steps} | minutes {round((s.total_time or 0)/60, 1)}")
        for name, sc in (s.scores or {}).items():
            print(f"  {name}: {sc.value}")
    if log.error:
        print("ERROR:", str(log.error.message)[:300])

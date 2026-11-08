#!/usr/bin/env bash
# Afternoon Kimi runs (pre-registered in experiment_log.md 2026-11-08 12:35). Waits for GLM.
set -u
cd ~/honeypot-control; source .venv/bin/activate; export PYTHONPATH=$PWD; git pull
K=openrouter/moonshotai/kimi-k3.1-pro
echo "waiting for any GLM run to finish..."
while true; do
  if pgrep -f "run_second[.]py.*glm" >/dev/null; then sleep 60; continue; fi
  sleep 120  # bridge the gap between GLM's two arms
  pgrep -f "run_second[.]py.*glm" >/dev/null || break
done
echo "===== 1/2 Kimi greedy (no --exp2): baseline + positive_control ====="
python run_second.py --arm baseline --pair-with positive_control --model $K --task-ids-file scout_tasks.txt --epochs 4 --parallel 6 --log-dir logs/kimi_greedy_baseline
python run_second.py --arm positive_control --model $K --task-ids-file scout_tasks.txt --epochs 4 --parallel 6 --log-dir logs/kimi_greedy_pc
python analysis/analyze.py --out analysis/out_kimi_greedy --arm baseline=logs/kimi_greedy_baseline --arm positive_control=logs/kimi_greedy_pc > ~/kimi_greedy.txt 2>&1
echo "===== 2/2 Live-15 downstream rerun ====="
python - <<'PY' > ~/live15_errors.txt 2>&1
from inspect_ai.log import list_eval_logs, read_eval_log
from collections import Counter
c = Counter()
for info in list_eval_logs("logs/kimi_live15", recursive=True):
    for s in (read_eval_log(info).samples or []):
        if s.error: c[str(s.error.message)[:160]] += 1
print("overnight live15 sample errors:", sum(c.values()))
for msg, k in c.most_common(5): print(k, msg)
PY
python run_second.py --exp2 --arm instant_halt_live15 --pair-with instant_halt_live15 --model $K --task-ids-file dev_tasks.txt --epochs 4 --parallel 6 --log-dir logs/kimi_live15b
python analysis/analyze.py --out analysis/out_kimi_live15b --arm exp2_kimi_baseline=logs/kimi_exp2_baseline --arm exp2_live=logs/kimi_live15,logs/kimi_live15b > ~/kimi_live15b.txt 2>&1
for f in ~/glm.txt ~/kimi_greedy.txt ~/live15_errors.txt ~/kimi_live15b.txt; do echo "===== $f ====="; cat "$f" 2>/dev/null; done > ~/afternoon_all.txt
echo AFTERNOON-DONE

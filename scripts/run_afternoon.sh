#!/usr/bin/env bash
# Afternoon runs (pre-registered in experiment_log.md 2026-11-08 11:45 and 12:35).
# Ordered fast-and-high-value first; each part writes its own report.
set -u
cd ~/honeypot-control; source .venv/bin/activate; export PYTHONPATH=$PWD; git pull
K=openrouter/moonshotai/kimi-k3.1-pro
G=openrouter/z-ai/glm-5.3-flash

echo "===== 1/3 Kimi greedy (no --exp2): incentive gate in a second model ====="
python run_second.py --arm baseline --pair-with positive_control --model $K --task-ids-file scout_tasks.txt --epochs 4 --parallel 6 --log-dir logs/kimi_greedy_baseline
python run_second.py --arm positive_control --model $K --task-ids-file scout_tasks.txt --epochs 4 --parallel 6 --log-dir logs/kimi_greedy_pc
python analysis/analyze.py --out analysis/out_kimi_greedy --arm baseline=logs/kimi_greedy_baseline --arm positive_control=logs/kimi_greedy_pc > ~/kimi_greedy.txt 2>&1

echo "===== 2/3 Live-15 natural boards: record overnight errors, then rerun ====="
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

echo "===== 3/3 GLM third model: forced-choice baseline + positive_control ====="
python run_second.py --exp2 --arm baseline --pair-with positive_control --model $G --task-ids-file scout_tasks.txt --epochs 4 --parallel 6 --log-dir logs/glm_baseline
python run_second.py --exp2 --arm positive_control --model $G --task-ids-file scout_tasks.txt --epochs 4 --parallel 6 --log-dir logs/glm_positive_control
python analysis/analyze.py --out analysis/out_glm --arm exp2_baseline=logs/glm_baseline --arm exp2_positive_control=logs/glm_positive_control > ~/glm.txt 2>&1

for f in ~/kimi_greedy.txt ~/live15_errors.txt ~/kimi_live15b.txt ~/glm.txt; do echo "===== $f ====="; cat "$f" 2>/dev/null; done > ~/afternoon_all.txt
echo AFTERNOON-DONE

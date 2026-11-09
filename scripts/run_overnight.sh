#!/usr/bin/env bash
# Overnight robustness runs (pre-registered in experiment_log.md 2026-11-08 00:10-00:15).
# All on one VM, serial, ordered by value so partial completion keeps the best.
# Run inside tmux:  bash scripts/run_overnight.sh
set -u
cd ~/honeypot-control
source .venv/bin/activate
export PYTHONPATH=$PWD
git pull
K=openrouter/moonshotai/kimi-k3.1-pro
G=z-ai/glm-5.3-flash
D=openrouter/deepseek/deepseek-v4.1-flash-1017

echo "===== 1/4 Kimi powered defender table (silent + delayed, 8 epochs) ====="
python run_second.py --exp2 --arm silent_alarm   --model $K --task-ids-file tasks/scout_tasks.txt --epochs 8 --parallel 6 --log-dir logs/kimi_silent
python run_second.py --exp2 --arm delayed_halt   --model $K --task-ids-file tasks/scout_tasks.txt --epochs 8 --parallel 6 --log-dir logs/kimi_delayed
python analysis/analyze.py --out analysis/out_kimi_def \
  --arm exp2_baseline=logs/kimi_exp2_baseline --arm exp2_delayed_halt=logs/kimi_delayed \
  --arm exp2_silent_alarm=logs/kimi_silent --arm exp2_positive_control=logs/kimi_exp2_positive_control \
  > ~/kimi_defender.txt 2>&1
echo "  -> ~/kimi_defender.txt"

echo "===== 2/4 Kimi live-scout harvest on 15 dev tasks ====="
python run_scouts.py --arm instant_halt --exp2 --snapshot-arm instant_halt_live15 --model $K \
  --task-ids-file tasks/dev_tasks.txt --parallel 6 --max-attempts 2 --log-dir logs/scouts_live15
python run_second.py --exp2 --arm instant_halt_live15 --pair-with instant_halt_live15 --model $K \
  --task-ids-file tasks/dev_tasks.txt --epochs 8 --parallel 6 --log-dir logs/kimi_live15
python analysis/analyze.py --out analysis/out_kimi_live15 \
  --arm exp2_kimi_baseline=logs/kimi_exp2_baseline --arm exp2_live=logs/kimi_live15 > ~/kimi_live15.txt 2>&1
python -c "import json,glob,collections; c=collections.Counter(json.load(open(f)).get('points_at_displayed') for f in glob.glob('snapshots/instant_halt_live15/*.json')); print('LIVE15 SCOUT BOARDS points_at_displayed:', dict(c))" >> ~/kimi_live15.txt 2>&1
echo "  -> ~/kimi_live15.txt"

echo "===== 3/4 GLM third-model replication (baseline + positive_control) ====="
python run_second.py --exp2 --arm baseline --pair-with positive_control --model $G --task-ids-file tasks/scout_tasks.txt --epochs 4 --parallel 6 --log-dir logs/glm_baseline
python run_second.py --exp2 --arm positive_control --model $G --task-ids-file tasks/scout_tasks.txt --epochs 4 --parallel 6 --log-dir logs/glm_positive_control
python analysis/analyze.py --out analysis/out_glm \
  --arm exp2_baseline=logs/glm_baseline --arm exp2_positive_control=logs/glm_positive_control > ~/glm.txt 2>&1
echo "  -> ~/glm.txt"

echo "===== 4/4 DeepSeek token-limit sensitivity (baseline, 2M, 2 epochs) ====="
python run_second.py --exp2 --arm baseline --pair-with positive_control --model $D --task-ids-file tasks/scout_tasks.txt --epochs 2 --parallel 6 --token-limit 2000000 --log-dir logs/ds_baseline_2M
python analysis/analyze.py --out analysis/out_ds2m --arm exp2_baseline_2M=logs/ds_baseline_2M > ~/ds2m.txt 2>&1
echo "  -> ~/ds2m.txt"

echo "ALLNIGHT-DONE"

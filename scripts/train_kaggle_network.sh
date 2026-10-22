#!/usr/bin/env bash
set -Eeuo pipefail

INPUT_PATH="${1:-datasets/network/flows.jsonl}"
MAX_ROWS="${MAX_ROWS:-30000}"
OUTPUT_DIR="${OUTPUT_DIR:-experiments/comparison/network}"

INSTALL_ARGS=()
if [[ "${INSTALL_XGBOOST:-0}" == "1" ]]; then
  INSTALL_ARGS+=(--install-xgboost)
fi

python3 scripts/train_kaggle_network.py \
  --input "$INPUT_PATH" \
  --max-rows "$MAX_ROWS" \
  --output-dir "$OUTPUT_DIR" \
  "${INSTALL_ARGS[@]}"

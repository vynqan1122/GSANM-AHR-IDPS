#!/usr/bin/env bash
set -Eeuo pipefail
python -m ai.network.train_xgboost
python -m ai.logs.train
python -m ai.graph.train
python -m ai.fusion.train


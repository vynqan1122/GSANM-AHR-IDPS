#!/usr/bin/env bash
set -Eeuo pipefail
python -m ai.network.evaluate
python -m ai.graph.evaluate
python -m ai.fusion.evaluate


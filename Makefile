.DEFAULT_GOAL := help
SHELL := /bin/sh

PHASE2_COMPOSE := docker compose --env-file .env \
	-f docker-compose.yml \
	-f sensors/suricata/compose.fragment.yml \
	-f sensors/falco/compose.fragment.yml \
	-f sensors/wazuh/compose.fragment.yml

.PHONY: help env install start stop restart status logs validate test \
	phase1-install phase1-start phase1-stop phase1-status phase1-logs \
	phase1-validate phase1-test \
	phase2-install phase2-start phase2-stop phase2-status phase2-logs \
	phase2-validate phase2-test sensors-status collect collect-benign collect-security-test \
	dataset-build train train-network train-log train-graph train-fusion train-all \
	evaluate ablation integration-test demo

help:
	@printf '%s\n' \
	  'AHR-IDPS Phase 1 + Phase 2 commands:' \
	  '  make install          Generate private config and pull all images' \
	  '  make start            Start/initialize Phase 1, then start sensors' \
	  '  make stop             Stop sensors, then lab; preserve all volumes' \
	  '  make restart          Stop and start all lab services' \
	  '  make status           Show all core and sensor containers' \
	  '  make logs             Follow all core and sensor logs' \
	  '  make sensors-status   Show sensor status' \
	  '  make train-all        Train all AI models' \
	  '  make evaluate         Evaluate trained models' \
	  '  make ablation         Run Phase 14 ablation experiments' \
	  '  make integration-test Run final Phase 14 acceptance' \
	  '  make demo             Run final end-to-end demo script' \
	  '  make validate         Run Phase 1 + Phase 2 static checks' \
	  '  make test             Run complete real-event Phase 2 acceptance' \
	  '  make phase1-test      Run the Phase 1 acceptance gate only' \
	  '  make phase2-test      Run Phase 2 plus its Phase 1 regression gate' \
	  '  make phase1-*         Targeted core lifecycle and acceptance commands' \
	  '  make phase2-*         Targeted sensor lifecycle and acceptance commands' \
	  '  make collect          Unavailable until Phase 5' \
	  '  make train            Unavailable until Phase 6' \
	  '  make evaluate         Unavailable until Phase 14'

env:
	@bash ./scripts/start_lab.sh --prepare-only
	@bash ./scripts/wazuh_prepare.sh

install:
	@bash ./scripts/start_lab.sh --install-only
	@bash ./scripts/start_sensors.sh --install-only

start:
	@bash ./scripts/start_lab.sh
	@bash ./scripts/start_sensors.sh

stop:
	@if [ -f .env ]; then \
	  bash ./scripts/stop_sensors.sh; \
	fi
	@bash ./scripts/stop_lab.sh

restart: stop start

status: env
	@$(PHASE2_COMPOSE) ps --all

logs: env
	@$(PHASE2_COMPOSE) logs --follow --tail 200

sensors-status:
	@bash ./scripts/sensors_check.sh

validate:
	@bash ./scripts/verify_phase1.sh --static-only
	@bash ./scripts/verify_phase2.sh --static-only

test:
	@bash ./scripts/verify_phase2.sh

phase1-install:
	@bash ./scripts/start_lab.sh --install-only

phase1-start:
	@bash ./scripts/start_lab.sh

phase1-stop:
	@bash ./scripts/stop_lab.sh

phase1-status:
	@bash ./scripts/start_lab.sh --prepare-only
	@docker compose --env-file .env ps --all

phase1-logs:
	@bash ./scripts/start_lab.sh --prepare-only
	@docker compose --env-file .env logs --follow --tail 200

phase1-validate:
	@bash ./scripts/verify_phase1.sh --static-only

phase1-test:
	@bash ./scripts/verify_phase1.sh

phase2-install:
	@bash ./scripts/start_sensors.sh --install-only

phase2-start:
	@bash ./scripts/start_sensors.sh

phase2-stop:
	@bash ./scripts/stop_sensors.sh

phase2-status: env
	@$(PHASE2_COMPOSE) ps --all suricata falco wazuh-manager

phase2-logs: env
	@$(PHASE2_COMPOSE) logs --follow --tail 200 suricata falco wazuh-manager

phase2-validate:
	@bash ./scripts/verify_phase2.sh --static-only

phase2-test:
	@bash ./scripts/verify_phase2.sh

collect:
	@python ./scripts/collect_dataset.py

collect-benign:
	@python ./scripts/generate_benign.py

collect-security-test:
	@bash ./scripts/verify_phase5.sh --static-only

dataset-build:
	@python ./scripts/build_dataset.py

train:
	@$(MAKE) train-all

train-network:
	@python -m ai.network.train_xgboost

train-log:
	@python -m ai.logs.train

train-graph:
	@python -m ai.graph.train

train-fusion:
	@python -m ai.fusion.train

train-all:
	@bash ./scripts/train_all.sh

evaluate:
	@bash ./scripts/evaluate.sh

ablation:
	@bash ./scripts/run_ablation.sh

integration-test:
	@bash ./scripts/verify_phase14.sh

demo:
	@bash ./scripts/demo.sh

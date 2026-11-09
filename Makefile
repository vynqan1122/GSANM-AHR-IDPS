.DEFAULT_GOAL := help
.PHONY: help build start stop status health

help:
	@printf '%s\n' 'make build | start | stop | status | health'

build:
	npm --prefix dashboard ci
	npm --prefix dashboard run typecheck
	npm --prefix dashboard run build

start:
	bash scripts/genti_control.sh start

stop:
	bash scripts/ahr_control.sh stop

status:
	bash scripts/genti_control.sh status

health:
	bash scripts/genti_control.sh health

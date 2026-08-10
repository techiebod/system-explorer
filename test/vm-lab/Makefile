.PHONY: help up reset down status inventory check

help:
	@./bin/vm-lab help

up:
	@./bin/vm-lab up all

reset:
	@./bin/vm-lab reset all

down:
	@./bin/vm-lab down all

status:
	@./bin/vm-lab status all

inventory:
	@./bin/vm-lab inventory

check:
	@bash -n bin/vm-lab
	@if command -v shellcheck >/dev/null 2>&1; then shellcheck bin/vm-lab; fi
	@nix flake check --no-build


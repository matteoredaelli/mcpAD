# Makefile for mcpAD — all tasks run through uv.
#
#   make sync                     install/refresh the dev environment
#   make lint                     ruff check + format check + pyrefly (strict)
#   make format                   apply ruff autofixes and formatting
#   make typecheck                pyrefly (strict) only
#   make start                    run the server (uses TRANSPORT / HOST / PORT)
#   make start-stdio              run over stdio (for MCP clients)
#   make start-http               run over streamable-http on HOST:PORT
#   make start-sse                run over sse on HOST:PORT
#
# Override transport/host/port, e.g.:
#   make start TRANSPORT=streamable-http PORT=9000
#   make start-http PORT=9000 HOST=0.0.0.0

UV_RUN := uv run --no-sync

# Start options (overridable on the command line).
TRANSPORT ?= stdio
HOST ?= 127.0.0.1
PORT ?= 8000

# Passed to the server entry point via environment variables.
START_ENV := MCP_TRANSPORT=$(TRANSPORT) MCP_HOST=$(HOST) MCP_PORT=$(PORT)

.DEFAULT_GOAL := help
.PHONY: help sync lint lint-check lint-format typecheck format \
        start start-stdio start-http start-sse

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

sync: ## Install/refresh the dev environment
	uv sync --group dev

lint: lint-check lint-format typecheck ## Run all linters (ruff check + format check + pyrefly)

lint-check: ## Run ruff check (lint rules)
	$(UV_RUN) ruff check src/

lint-format: ## Run ruff format --check (formatting)
	$(UV_RUN) ruff format --check src/

typecheck: ## Run pyrefly (strict) only
	$(UV_RUN) pyrefly check

format: ## Apply ruff autofixes and formatting
	$(UV_RUN) ruff check --fix src/
	$(UV_RUN) ruff format src/

start: ## Run the server (TRANSPORT / HOST / PORT overridable)
	$(START_ENV) $(UV_RUN) mcpad

start-stdio: ## Run over stdio (for MCP clients)
	$(MAKE) start TRANSPORT=stdio

start-http: ## Run over streamable-http on HOST:PORT
	$(MAKE) start TRANSPORT=streamable-http

start-sse: ## Run over sse on HOST:PORT
	$(MAKE) start TRANSPORT=sse

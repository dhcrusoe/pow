.DEFAULT_GOAL := help
PY  := python3
LOG := tmp/pow-log
OUT := tmp/site
export PYTHONPATH := packages:.

help: ## Show this help
	@grep -hE '^[a-z-]+:.*##' $(MAKEFILE_LIST) | sed 's/:.*##/\t/' | expand -t22

install: ## Install the package and dev extras
	$(PY) -m pip install -e ".[dev]"

log: ## Seed a local log, plus a corpus of records built to fail
	rm -rf tmp && $(PY) -m scripts.seed_log $(LOG)
	@cd $(LOG) && git init -q -b main 2>/dev/null || true; \
	  git add -A && git -c user.email=pow@localhost -c user.name=pow \
	  commit -qm "seed" 2>/dev/null || true

env: ## Create .env from the example (gitignored, mode 600)
	@test -f .env && echo ".env already exists; leaving it alone" || { \
	  cp .env.example .env && chmod 600 .env && echo "wrote .env — fill in GITHUB_TOKEN"; }

api: ## Run the ingest API against the local log (no token needed)
	LOG_BACKEND=local LOG_PATH=$(LOG) FLASK_APP=pow_api.main:create_app \
	  $(PY) -m flask run --port 8000

api-github: ## Run the ingest API against the REAL log (reads .env)
	@test -f .env || { echo "no .env — run 'make env' first"; exit 1; }
	@echo "WARNING: records written now land in a public append-only log."
	@echo "They cannot be edited or removed. Ctrl-C within 5s to stop."
	@sleep 5
	@set -a && . ./.env && set +a && \
	  FLASK_APP=pow_api.main:create_app $(PY) -m flask run --port 8000

generate: ## Build the read plane from the local log
	$(PY) -m pow_generate $(LOG) $(OUT)

serve: generate ## Build and serve the site
	@echo "http://localhost:8080" && cd $(OUT) && $(PY) -m http.server 8080

verify: ## Verify the first unsettled claim as slate
	@CLAIM=$$($(PY) -c "import json,pathlib;q=json.loads(pathlib.Path('$(OUT)/queue.json').read_text());print(q['unverified'][0].replace('sha256:',''))"); \
	 KEY=$$($(PY) -c "import json;print(json.load(open('tmp/keys.json'))['slate']['private'])"); \
	 $(PY) -m pow_verify $(LOG)/claims/$$CLAIM.json --as slate --key "$$KEY"

validate: ## Run the CI validator over the whole log (what the Action runs)
	$(PY) -m scripts.validate_log $(LOG)

negative: ## Assert every record built to fail is rejected
	$(PY) -m scripts.validate_log tmp/negative --expect-failure

test: ## Run the suite
	$(PY) -m pytest -q

lint: ## Lint and type-check the pure library
	ruff check packages tests scripts && mypy --strict packages/pow_core

check: test lint validate negative ## Everything CI runs

clean: ## Remove local state
	rm -rf tmp .pytest_cache

.PHONY: help install env log api api-github generate serve verify validate negative test lint check clean

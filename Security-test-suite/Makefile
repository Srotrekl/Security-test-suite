.PHONY: help setup test test-api test-ui test-smoke test-critical lint format report clean docker-up docker-down

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

setup: ## Install dependencies and prepare environment
	pip install -r requirements.txt -r requirements-dev.txt
	playwright install chromium
	cp -n .env.example .env 2>/dev/null || true
	@echo "Setup complete. Edit .env if needed, then run: make docker-up"

test: ## Run all tests
	pytest -v

test-api: ## Run API security tests only
	pytest tests/api/ -v

test-ui: ## Run UI security tests only (headless)
	pytest tests/ui/ -v

test-smoke: ## Run smoke tests (fast subset)
	pytest -m smoke -v

test-critical: ## Run critical severity tests only
	pytest -m critical -v

lint: ## Run linting (ruff check + format check)
	ruff check .
	ruff format --check .

format: ## Auto-format code with ruff
	ruff check --fix .
	ruff format .

report: ## Open the latest HTML test report
	@echo "Opening reports/report.html ..."
	@python -m webbrowser reports/report.html 2>/dev/null || open reports/report.html 2>/dev/null || xdg-open reports/report.html 2>/dev/null || echo "Open reports/report.html manually"

clean: ## Remove caches, reports, and build artifacts
	rm -rf reports/*.html reports/*.json reports/screenshots/
	rm -rf .pytest_cache __pycache__ .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

docker-up: ## Start Juice Shop (+ ZAP with: make docker-up PROFILE=scan)
	docker compose up juice-shop -d
	@echo "Waiting for Juice Shop to start..."
	@for i in $$(seq 1 15); do curl -sf http://localhost:3000 > /dev/null && echo "Juice Shop is ready!" && break || sleep 2; done

docker-down: ## Stop all Docker containers
	docker compose --profile scan down

docker-zap: ## Run ZAP baseline scan
	docker compose --profile scan up zap

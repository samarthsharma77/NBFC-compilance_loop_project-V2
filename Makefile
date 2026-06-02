# ═══════════════════════════════════════════════════════════════════════════════
# ComplianceLoop — Makefile
# All developer and operational commands in one place.
# Run `make help` to see all available targets.
# ═══════════════════════════════════════════════════════════════════════════════

.PHONY: help dev dev-down migrate migrate-demo migrate-test seed-demo \
        build-index swap-index run-api run-worker run-beat run-flower \
        test test-unit test-integration test-e2e test-coverage \
        lint format typecheck check install install-dev install-all \
        deploy rollback rotate-secrets verify-audit break-glass \
        pg-backup docker-build docker-push clean logs

# ── Colours ──────────────────────────────────────────────────────────────────
CYAN    := \033[0;36m
GREEN   := \033[0;32m
YELLOW  := \033[0;33m
RED     := \033[0;31m
RESET   := \033[0m
BOLD    := \033[1m

# ── Configuration ─────────────────────────────────────────────────────────────
PYTHON          := python3.11
PIP             := $(PYTHON) -m pip
DOCKER_COMPOSE  := docker compose
IMAGE_NAME      := complianceloop
IMAGE_TAG       ?= latest
REGISTRY        ?= ghcr.io/your-org
SERVER_HOST     ?= your-production-server.com
SERVER_USER     ?= deploy

# ── Default target ────────────────────────────────────────────────────────────
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo ""
	@echo "$(BOLD)$(CYAN)ComplianceLoop — Available Make Targets$(RESET)"
	@echo ""
	@echo "$(BOLD)Infrastructure:$(RESET)"
	@grep -E '^(dev|dev-down|logs).*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Database:$(RESET)"
	@grep -E '^migrate.*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@grep -E '^seed.*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Application:$(RESET)"
	@grep -E '^run.*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)FAISS Index:$(RESET)"
	@grep -E '^(build|swap)-index.*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Testing:$(RESET)"
	@grep -E '^test.*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Code Quality:$(RESET)"
	@grep -E '^(lint|format|typecheck|check).*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Dependencies:$(RESET)"
	@grep -E '^install.*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Operations:$(RESET)"
	@grep -E '^(deploy|rollback|rotate|verify|break|pg-backup).*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Docker:$(RESET)"
	@grep -E '^docker.*:.*##' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*##"}; {printf "  $(CYAN)%-30s$(RESET) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(BOLD)Variables (override with make TARGET VAR=value):$(RESET)"
	@echo "  $(CYAN)IMAGE_TAG$(RESET)     Docker image tag (default: latest)"
	@echo "  $(CYAN)REGISTRY$(RESET)      Docker registry (default: ghcr.io/your-org)"
	@echo "  $(CYAN)SERVER_HOST$(RESET)   Production server hostname"
	@echo "  $(CYAN)ID$(RESET)            Decision/application ID for verify-audit, break-glass"
	@echo ""

# ── Infrastructure ────────────────────────────────────────────────────────────
dev: ## Start all infrastructure containers (Postgres, Redis, MinIO, Prometheus, Grafana, Vault)
	@echo "$(CYAN)Starting infrastructure stack...$(RESET)"
	@cp -n .env.example .env 2>/dev/null || true
	$(DOCKER_COMPOSE) up -d postgres redis minio prometheus grafana vault
	@echo "$(GREEN)Infrastructure ready.$(RESET)"
	@echo "  Postgres:   localhost:5432"
	@echo "  Redis:      localhost:6379"
	@echo "  MinIO:      http://localhost:9000  (console: http://localhost:9001)"
	@echo "  Prometheus: http://localhost:9090"
	@echo "  Grafana:    http://localhost:3001  (admin/admin)"
	@echo "  Vault:      http://localhost:8200  (token: root)"

dev-down: ## Stop and remove all containers (keeps volumes)
	@echo "$(YELLOW)Stopping containers...$(RESET)"
	$(DOCKER_COMPOSE) down
	@echo "$(GREEN)Done.$(RESET)"

dev-clean: ## Stop all containers AND remove volumes (full reset — DATA LOSS)
	@echo "$(RED)WARNING: This will delete all data volumes!$(RESET)"
	@read -p "Are you sure? [y/N] " confirm && [ "$$confirm" = "y" ]
	$(DOCKER_COMPOSE) down -v --remove-orphans
	@echo "$(GREEN)Full reset complete.$(RESET)"

logs: ## Tail logs from all running containers
	$(DOCKER_COMPOSE) logs -f --tail=100

logs-%: ## Tail logs from a specific service: make logs-api
	$(DOCKER_COMPOSE) logs -f --tail=100 $*

# ── Database ──────────────────────────────────────────────────────────────────
migrate: ## Run Alembic migrations on production database
	@echo "$(CYAN)Running database migrations...$(RESET)"
	$(PYTHON) -m alembic upgrade head
	@echo "$(GREEN)Migrations complete.$(RESET)"

migrate-demo: ## Run Alembic migrations on demo database
	@echo "$(CYAN)Running demo database migrations...$(RESET)"
	POSTGRES_DSN=$${DEMO_POSTGRES_DSN} $(PYTHON) -m alembic upgrade head
	@echo "$(GREEN)Demo migrations complete.$(RESET)"

migrate-test: ## Run Alembic migrations on test database
	@echo "$(CYAN)Running test database migrations...$(RESET)"
	POSTGRES_DSN=$${TEST_POSTGRES_DSN} $(PYTHON) -m alembic upgrade head
	@echo "$(GREEN)Test migrations complete.$(RESET)"

migrate-rollback: ## Rollback last Alembic migration
	@echo "$(YELLOW)Rolling back last migration...$(RESET)"
	$(PYTHON) -m alembic downgrade -1
	@echo "$(GREEN)Rollback complete.$(RESET)"

migrate-history: ## Show Alembic migration history
	$(PYTHON) -m alembic history --verbose

migrate-current: ## Show current Alembic revision
	$(PYTHON) -m alembic current

seed-demo: ## Seed demo database with 25-30 synthetic applicants
	@echo "$(CYAN)Seeding demo database...$(RESET)"
	$(PYTHON) db/seeds/demo_seed.py
	@echo "$(GREEN)Demo database seeded.$(RESET)"

seed-demo-reset: ## Wipe and re-seed demo database
	@echo "$(YELLOW)Resetting demo database...$(RESET)"
	DEMO_POSTGRES_DSN=$${DEMO_POSTGRES_DSN} $(PYTHON) -m alembic downgrade base
	DEMO_POSTGRES_DSN=$${DEMO_POSTGRES_DSN} $(PYTHON) -m alembic upgrade head
	$(PYTHON) db/seeds/demo_seed.py --reset
	@echo "$(GREEN)Demo database reset and re-seeded.$(RESET)"

# ── FAISS Index ───────────────────────────────────────────────────────────────
build-index: ## Build FAISS index from regulatory corpus in MinIO
	@echo "$(CYAN)Building FAISS index...$(RESET)"
	@bash scripts/build_faiss_index.sh
	@echo "$(GREEN)FAISS index build complete.$(RESET)"

swap-index: ## Manually trigger safe FAISS index swap (runs health check first)
	@echo "$(CYAN)Triggering FAISS index swap...$(RESET)"
	@bash scripts/swap_faiss_index.sh
	@echo "$(GREEN)FAISS index swap complete.$(RESET)"

index-health: ## Run golden-corpus health check against active FAISS index
	@echo "$(CYAN)Running FAISS index health check...$(RESET)"
	$(PYTHON) -c "from retrieval.index_manager import IndexManager; import asyncio; asyncio.run(IndexManager().health_check())"

# ── Application ───────────────────────────────────────────────────────────────
run-api: ## Start FastAPI development server with hot reload
	@echo "$(CYAN)Starting FastAPI server on :8000...$(RESET)"
	$(PYTHON) -m uvicorn api.main:app \
		--host 0.0.0.0 \
		--port 8000 \
		--reload \
		--reload-dir api \
		--reload-dir pipeline \
		--reload-dir audit \
		--reload-dir retrieval \
		--reload-dir models \
		--log-level info

run-worker: ## Start Celery worker (pipeline + retro-eval tasks)
	@echo "$(CYAN)Starting Celery worker...$(RESET)"
	$(PYTHON) -m celery -A workers.celery_app worker \
		--loglevel=info \
		--concurrency=4 \
		--queues=pipeline,retro_eval,notifications \
		--hostname=worker@%h

run-beat: ## Start Celery Beat scheduler (scraper + calibration schedules)
	@echo "$(CYAN)Starting Celery Beat scheduler...$(RESET)"
	$(PYTHON) -m celery -A workers.celery_app beat \
		--loglevel=info \
		--scheduler=celery.beat:PersistentScheduler \
		--schedule=/tmp/celerybeat-schedule

run-scraper: ## Start Celery worker dedicated to scraper queue only
	@echo "$(CYAN)Starting scraper worker...$(RESET)"
	$(PYTHON) -m celery -A workers.celery_app worker \
		--loglevel=info \
		--concurrency=2 \
		--queues=scraper \
		--hostname=scraper@%h

run-flower: ## Start Flower Celery monitoring UI on :5555
	@echo "$(CYAN)Starting Flower on :5555...$(RESET)"
	$(PYTHON) -m celery -A workers.celery_app flower \
		--port=5555 \
		--basic-auth=$${FLOWER_BASIC_AUTH}

run-all: dev migrate ## Start infrastructure + run migrations (full local dev setup)
	@echo "$(GREEN)Full stack ready. Start api/worker/beat manually.$(RESET)"

# ── Testing ───────────────────────────────────────────────────────────────────
test: ## Run ALL tests (unit + integration + e2e)
	@echo "$(CYAN)Running full test suite...$(RESET)"
	$(PYTHON) -m pytest -v --tb=short

test-unit: ## Run unit tests only (no Docker required — fast)
	@echo "$(CYAN)Running unit tests...$(RESET)"
	$(PYTHON) -m pytest -v -m "unit" --tb=short --no-cov

test-integration: ## Run integration tests (requires Docker — TestContainers)
	@echo "$(CYAN)Running integration tests (Docker required)...$(RESET)"
	$(PYTHON) -m pytest -v -m "integration" --tb=short

test-e2e: ## Run end-to-end tests (requires full stack running)
	@echo "$(CYAN)Running E2E tests...$(RESET)"
	$(PYTHON) -m pytest -v -m "e2e" --tb=short

test-coverage: ## Run tests with full coverage report
	@echo "$(CYAN)Running tests with coverage...$(RESET)"
	$(PYTHON) -m pytest --cov=. --cov-report=html:htmlcov --cov-report=term-missing
	@echo "$(GREEN)Coverage report: htmlcov/index.html$(RESET)"

test-file: ## Run tests in a specific file: make test-file FILE=pipeline/tests/test_document_agent.py
	$(PYTHON) -m pytest $(FILE) -v --tb=long

test-watch: ## Run tests in watch mode (re-runs on file changes)
	$(PYTHON) -m pytest-watch -- -v -m "unit"

test-parallel: ## Run unit tests in parallel (faster CI)
	$(PYTHON) -m pytest -v -m "unit" -n auto --dist=loadfile

# ── Code Quality ──────────────────────────────────────────────────────────────
lint: ## Run ruff linter
	@echo "$(CYAN)Running ruff linter...$(RESET)"
	$(PYTHON) -m ruff check . --show-fixes
	@echo "$(GREEN)Lint passed.$(RESET)"

lint-fix: ## Run ruff linter and auto-fix issues
	@echo "$(CYAN)Running ruff linter with auto-fix...$(RESET)"
	$(PYTHON) -m ruff check . --fix
	@echo "$(GREEN)Lint fixes applied.$(RESET)"

format: ## Run black formatter
	@echo "$(CYAN)Running black formatter...$(RESET)"
	$(PYTHON) -m black .
	@echo "$(GREEN)Format complete.$(RESET)"

format-check: ## Check formatting without modifying files (for CI)
	@echo "$(CYAN)Checking formatting...$(RESET)"
	$(PYTHON) -m black . --check --diff
	@echo "$(GREEN)Format check passed.$(RESET)"

typecheck: ## Run mypy type checker
	@echo "$(CYAN)Running mypy type checker...$(RESET)"
	$(PYTHON) -m mypy . --config-file pyproject.toml
	@echo "$(GREEN)Type check passed.$(RESET)"

check: format-check lint typecheck ## Run all code quality checks (CI gate)
	@echo "$(GREEN)All quality checks passed.$(RESET)"

security-check: ## Run bandit security scanner
	@echo "$(CYAN)Running bandit security scan...$(RESET)"
	$(PYTHON) -m bandit -r . -x "*/tests/*,*/migrations/*,frontend/,infra/" -f screen
	@echo "$(GREEN)Security scan complete.$(RESET)"

# ── Dependencies ──────────────────────────────────────────────────────────────
install: ## Install base + api + security requirements
	@echo "$(CYAN)Installing production dependencies...$(RESET)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements/base.txt
	$(PIP) install -r requirements/security.txt
	$(PIP) install -r requirements/api.txt
	@echo "$(GREEN)Dependencies installed.$(RESET)"

install-pipeline: ## Install pipeline dependencies (includes PyTorch CPU — large download)
	@echo "$(CYAN)Installing pipeline dependencies (this may take a while)...$(RESET)"
	$(PIP) install -r requirements/pipeline.txt
	@echo "$(GREEN)Pipeline dependencies installed.$(RESET)"

install-worker: ## Install worker dependencies (includes pipeline + scraper)
	@echo "$(CYAN)Installing worker dependencies...$(RESET)"
	$(PIP) install -r requirements/pipeline.txt
	$(PIP) install -r requirements/scraper.txt
	$(PIP) install -r requirements/worker.txt
	@echo "$(GREEN)Worker dependencies installed.$(RESET)"

install-dev: ## Install all dependencies including dev/test tools
	@echo "$(CYAN)Installing all dependencies (dev mode)...$(RESET)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements/base.txt
	$(PIP) install -r requirements/security.txt
	$(PIP) install -r requirements/api.txt
	$(PIP) install -r requirements/pipeline.txt
	$(PIP) install -r requirements/scraper.txt
	$(PIP) install -r requirements/worker.txt
	$(PIP) install -r requirements/dev.txt
	@echo "$(CYAN)Installing Playwright browsers...$(RESET)"
	$(PYTHON) -m playwright install chromium
	@echo "$(CYAN)Installing pre-commit hooks...$(RESET)"
	$(PYTHON) -m pre_commit install
	@echo "$(GREEN)All dev dependencies installed.$(RESET)"

install-all: install-dev ## Alias for install-dev

# ── Operations ────────────────────────────────────────────────────────────────
deploy: ## Deploy to production server via SSH
	@echo "$(CYAN)Deploying to $(SERVER_HOST)...$(RESET)"
	@bash scripts/deploy.sh $(SERVER_HOST) $(SERVER_USER) $(IMAGE_TAG)
	@echo "$(GREEN)Deployment complete.$(RESET)"

rollback: ## Rollback production to previous Docker image
	@echo "$(YELLOW)Rolling back production deployment...$(RESET)"
	@bash scripts/rollback.sh $(SERVER_HOST) $(SERVER_USER)
	@echo "$(GREEN)Rollback complete.$(RESET)"

rotate-secrets: ## Rotate HMAC and AES keys with overlap window
	@echo "$(YELLOW)Rotating cryptographic keys...$(RESET)"
	@read -p "This will rotate SERVER_HMAC_KEY and AES_KEY. Continue? [y/N] " confirm && [ "$$confirm" = "y" ]
	@bash scripts/rotate_secrets.sh
	@echo "$(GREEN)Key rotation complete. Update .env on all servers.$(RESET)"

verify-audit: ## Verify audit record integrity: make verify-audit ID=<decision_id>
ifndef ID
	$(error ID is required: make verify-audit ID=<decision_id>)
endif
	@echo "$(CYAN)Verifying audit record $(ID)...$(RESET)"
	@bash scripts/verify_audit_record.sh $(ID)

break-glass: ## Activate breach response: make break-glass APP=<application_id>
ifndef APP
	$(error APP is required: make break-glass APP=<application_id>)
endif
	@echo "$(RED)ACTIVATING BREACH RESPONSE FOR $(APP)$(RESET)"
	@read -p "This will flag the record, freeze retro-eval jobs, and queue notifications. Continue? [y/N] " confirm && [ "$$confirm" = "y" ]
	@bash scripts/break_glass.sh $(APP)
	@echo "$(RED)Breach response activated. Check notification_outbox for queued alerts.$(RESET)"

pg-backup: ## Manually trigger PostgreSQL backup to MinIO
	@echo "$(CYAN)Running PostgreSQL backup...$(RESET)"
	@bash scripts/pg_backup.sh
	@echo "$(GREEN)Backup complete.$(RESET)"

generate-api-key: ## Generate a new API key: make generate-api-key SCOPE=read
	@echo "$(CYAN)Generating API key...$(RESET)"
	@bash scripts/generate_api_key.sh $(SCOPE)

# ── Docker ────────────────────────────────────────────────────────────────────
docker-build: ## Build all Docker images
	@echo "$(CYAN)Building Docker images...$(RESET)"
	docker build --target api    -t $(REGISTRY)/$(IMAGE_NAME)-api:$(IMAGE_TAG) .
	docker build --target worker -t $(REGISTRY)/$(IMAGE_NAME)-worker:$(IMAGE_TAG) .
	@echo "$(GREEN)Images built.$(RESET)"

docker-push: ## Push Docker images to registry
	@echo "$(CYAN)Pushing images to $(REGISTRY)...$(RESET)"
	docker push $(REGISTRY)/$(IMAGE_NAME)-api:$(IMAGE_TAG)
	docker push $(REGISTRY)/$(IMAGE_NAME)-worker:$(IMAGE_TAG)
	@echo "$(GREEN)Images pushed.$(RESET)"

docker-pull: ## Pull latest images from registry
	docker pull $(REGISTRY)/$(IMAGE_NAME)-api:$(IMAGE_TAG)
	docker pull $(REGISTRY)/$(IMAGE_NAME)-worker:$(IMAGE_TAG)

# ── Utilities ─────────────────────────────────────────────────────────────────
clean: ## Remove Python cache files, coverage reports, build artifacts
	@echo "$(CYAN)Cleaning up...$(RESET)"
	find . -type d -name "__pycache__" -not -path "*/node_modules/*" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -not -path "*/node_modules/*" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -not -path "*/node_modules/*" -delete 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/ .coverage dist/ build/ 2>/dev/null || true
	@echo "$(GREEN)Clean complete.$(RESET)"

env-check: ## Validate that all required environment variables are set
	@echo "$(CYAN)Checking environment variables...$(RESET)"
	$(PYTHON) -c "
from pydantic_settings import BaseSettings
import sys
try:
    from api.config import Settings
    s = Settings()
    print('$(GREEN)All required environment variables are set.$(RESET)')
except Exception as e:
    print(f'$(RED)Missing or invalid environment variable: {e}$(RESET)')
    sys.exit(1)
"

shell: ## Open a Python shell with app context loaded
	$(PYTHON) -c "
import asyncio
from api.config import settings
from db.session import get_db
print('ComplianceLoop shell. Settings loaded. Use asyncio.run() for async calls.')
" && $(PYTHON) -i -c "from api.config import settings; print('Settings:', settings.APP_ENV)"

version: ## Show current application version
	@echo "ComplianceLoop v$(shell grep '^version' pyproject.toml | head -1 | cut -d'"' -f2)"
	@echo "Python: $(shell $(PYTHON) --version)"
	@echo "Docker: $(shell docker --version)"
# ═══════════════════════════════════════════════════════════════════════════════
# ComplianceLoop — Multi-stage Dockerfile
#
# Stages:
#   base      → Python base with system deps
#   builder   → Install all Python packages
#   api       → Production API image (FastAPI + Uvicorn)
#   worker    → Production worker image (Celery + pipeline + scraper)
#
# Build targets:
#   docker build --target api    -t complianceloop-api .
#   docker build --target worker -t complianceloop-worker .
# ═══════════════════════════════════════════════════════════════════════════════

# ── Stage 1: base ─────────────────────────────────────────────────────────────
FROM python:3.11-slim-bookworm AS base

# Metadata
LABEL maintainer="ComplianceLoop Engineering"
LABEL org.opencontainers.image.title="ComplianceLoop"
LABEL org.opencontainers.image.description="AI-Native NBFC Compliance Operating System"
LABEL org.opencontainers.image.version="1.0.0"

# Prevent .pyc files and enable unbuffered stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    PYTHONHASHSEED=random \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_DEFAULT_TIMEOUT=100

# System dependencies
# - libpq-dev: PostgreSQL client library (for asyncpg)
# - libgomp1: OpenMP (required by faiss-cpu)
# - curl: health checks
# - ca-certificates: HTTPS to external services (RBI, OFAC, etc.)
# - chromium + chromium-driver: Playwright headless browser (worker only)
RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq-dev \
        libgomp1 \
        libglib2.0-0 \
        libsm6 \
        libxext6 \
        libxrender-dev \
        libgl1-mesa-glx \
        curl \
        ca-certificates \
        wget \
        gnupg \
        git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN groupadd --gid 1001 appgroup \
    && useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

# Set working directory
WORKDIR /app

# Create required directories with correct permissions
RUN mkdir -p \
        /app/retrieval/index_data/index_active \
        /app/retrieval/index_data/index_staging \
        /app/retrieval/index_data/index_backup \
        /app/logs \
    && chown -R appuser:appgroup /app


# ── Stage 2: builder ──────────────────────────────────────────────────────────
FROM base AS builder

# Install build tools needed for some packages
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        gcc \
        g++ \
        make \
        pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip
RUN pip install --upgrade pip setuptools wheel

# Copy requirements files
COPY requirements/ /app/requirements/

# Install base + security requirements (shared across all targets)
RUN pip install \
        -r /app/requirements/base.txt \
        -r /app/requirements/security.txt


# ── Stage 3: api ──────────────────────────────────────────────────────────────
FROM builder AS api-builder

# Install API-specific requirements
RUN pip install -r /app/requirements/api.txt

# Install pipeline requirements (API needs to submit tasks + read results)
# We do NOT install scraper deps in the API image — keep it lean
RUN pip install -r /app/requirements/pipeline.txt

# ── API final image ───────────────────────────────────────────────────────────
FROM base AS api

# Copy installed packages from builder
COPY --from=api-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=api-builder /usr/local/bin /usr/local/bin

# Copy application source
# Copy only the modules the API needs — not scraper, not full pipeline
COPY --chown=appuser:appgroup api/           /app/api/
COPY --chown=appuser:appgroup pipeline/      /app/pipeline/
COPY --chown=appuser:appgroup audit/         /app/audit/
COPY --chown=appuser:appgroup retrieval/     /app/retrieval/
COPY --chown=appuser:appgroup models/        /app/models/
COPY --chown=appuser:appgroup db/            /app/db/
COPY --chown=appuser:appgroup workers/       /app/workers/
COPY --chown=appuser:appgroup notifications/ /app/notifications/
COPY --chown=appuser:appgroup dpdp/          /app/dpdp/
COPY --chown=appuser:appgroup observability/ /app/observability/
COPY --chown=appuser:appgroup security/      /app/security/
COPY --chown=appuser:appgroup demo/          /app/demo/
COPY --chown=appuser:appgroup calibration/   /app/calibration/
COPY --chown=appuser:appgroup retro_eval/    /app/retro_eval/
COPY --chown=appuser:appgroup pyproject.toml /app/

# Switch to non-root user
USER appuser

# Health check — calls /health endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Default command — override in docker-compose for different configs
CMD ["uvicorn", "api.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "4", \
     "--loop", "uvloop", \
     "--http", "httptools", \
     "--access-log", \
     "--log-level", "info"]


# ── Stage 4: worker-builder ───────────────────────────────────────────────────
FROM builder AS worker-builder

# Install ALL requirements — worker runs pipeline, scraper, calibration, retro-eval
RUN pip install -r /app/requirements/api.txt
RUN pip install -r /app/requirements/pipeline.txt
RUN pip install -r /app/requirements/scraper.txt
RUN pip install -r /app/requirements/worker.txt

# Install Playwright browsers (headless Chromium for RBI JS pages)
RUN pip install playwright==1.46.0 \
    && playwright install chromium \
    && playwright install-deps chromium


# ── Worker final image ────────────────────────────────────────────────────────
FROM base AS worker

# Install Chromium system dependencies (needed by Playwright in final image)
RUN apt-get update && apt-get install -y --no-install-recommends \
        chromium \
        chromium-driver \
        libnss3 \
        libnspr4 \
        libatk1.0-0 \
        libatk-bridge2.0-0 \
        libcups2 \
        libdrm2 \
        libxkbcommon0 \
        libxcomposite1 \
        libxdamage1 \
        libxfixes3 \
        libxrandr2 \
        libgbm1 \
        libasound2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from worker-builder
COPY --from=worker-builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=worker-builder /usr/local/bin /usr/local/bin
# Copy Playwright browser binaries
COPY --from=worker-builder /root/.cache/ms-playwright /home/appuser/.cache/ms-playwright

# Copy full application source (worker needs all modules)
COPY --chown=appuser:appgroup . /app/

# Set Playwright to use system Chromium
ENV PLAYWRIGHT_BROWSERS_PATH=/home/appuser/.cache/ms-playwright
ENV PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1

# Switch to non-root user
USER appuser

# Health check — check Celery worker is responsive
HEALTHCHECK --interval=60s --timeout=30s --start-period=60s --retries=3 \
    CMD celery -A workers.celery_app inspect ping --timeout=10 || exit 1

# Default command — Celery worker for pipeline + retro_eval + notifications queues
# Override in docker-compose for beat scheduler or scraper-only worker
CMD ["celery", "-A", "workers.celery_app", "worker", \
     "--loglevel=info", \
     "--concurrency=4", \
     "--queues=pipeline,retro_eval,notifications", \
     "--hostname=worker@%h", \
     "--without-gossip", \
     "--without-mingle", \
     "--without-heartbeat"]
# ComplianceLoop

**AI-Native NBFC Compliance Operating System**

ComplianceLoop is a production-grade, multi-agent compliance decisioning system built for Non-Banking Financial Companies (NBFCs) operating under the Reserve Bank of India (RBI) regulatory framework and the Digital Personal Data Protection (DPDP) Act 2023. It treats compliance as a real-time, explainable decision problem — not a static checklist — and closes the loop between regulation, decisioning, audit, and continuous learning.

---

## What it does

Every loan application submitted to an NBFC must pass through a gauntlet of regulatory checks: KYC document validity, sanctions screening, time-based expiry windows, financial feasibility ratios, and alignment with the latest RBI circulars. Today, most NBFCs do this manually or with fragmented tools, creating inconsistency, audit risk, and slow decisions.

ComplianceLoop collapses all of this into a single deterministic LangGraph pipeline that:

- Fans out to five specialist agents simultaneously (document, sanctions, temporal, transaction, RAG)
- Synthesises all agent signals into an `APPROVE`, `REVIEW`, or `REJECT` decision with an explicit confidence score
- Writes a tamper-evident audit record **before** the API responds — compliance evidence exists even if downstream systems fail
- Continuously scrapes RBI and DPDP sources for regulatory changes, re-indexes the retrieval corpus, and re-evaluates past decisions that were affected by the change
- Notifies applicants and reviewers when a regulatory change flips a prior decision
- Learns from reviewer corrections through a calibration engine that adjusts confidence thresholds without code deployment

---

## Architecture overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Ingestion & Gateway                          │
│  FastAPI + Nginx + DPDP consent gate + Redis rate limiter           │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                  LangGraph Pipeline (deterministic DAG)             │
│                                                                     │
│   Router Node                                                       │
│       │                                                             │
│   ┌───┼───────────────────────────┐                                 │
│   ▼   ▼       ▼         ▼        ▼                                  │
│  Doc  Sanctions  Temporal  Transaction  RAG                         │
│  Agent  Agent    Agent     Agent        Agent                       │
│   │   │       │         │        │                                  │
│   └───┴───────┴─────────┴────────┘                                 │
│                        │                                            │
│                Decision Node                                        │
│                        │                                            │
│              Audit Writer (pre-response)                            │
│                        │                                            │
│              Outcome Router → APPROVE / REVIEW / REJECT             │
└─────────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│                 Persistence Layer                                   │
│  PostgreSQL  │  MinIO (audit payloads)  │  FAISS  │  Redis          │
└─────────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│           Regulatory Intelligence + Retro-Eval Loop                 │
│  Scrapy/Playwright → Delta Detector → Tagger → FAISS refresh        │
│  → Audit trail filter → Batch re-eval → Decision change notify      │
└─────────────────────────────────────────────────────────────────────┘
                                │
┌───────────────────────────────▼─────────────────────────────────────┐
│           Feedback & Observability                                  │
│  Calibration engine  │  Prometheus  │  Grafana  │  structlog        │
└─────────────────────────────────────────────────────────────────────┘
```

---

## The five specialist agents

| Agent | Responsibility | Hard gate? |
|---|---|---|
| **Document** | KYC artifact presence, PAN, OVD validity, income proof, V-CIP, hash integrity | Yes — missing mandatory docs = REJECT |
| **Sanctions** | PAN HMAC exact match + name fuzzy match against UNSC, OFAC, MHA, SEBI, RBI Defaulter lists | Yes — any confirmed hit = REJECT |
| **Temporal** | KYC update intervals, OVD expiry, income proof recency, bureau report age, guideline effective date windows | Yes — expired KYC = REJECT |
| **Transaction** | FOIR computation, Net Take-Home feasibility, DTI ratio, LTV for secured loans, sector exposure | Yes — FOIR breach = REJECT |
| **RAG** | Retrieves top-5 relevant passages from indexed RBI/DPDP corpus; synthesises regulatory basis for rationale chain | No — context enrichment only |

All agents run in parallel. The decision node aggregates their signal weights with configurable per-agent weights (stored in `guideline_versions.parameters`, not hardcoded).

---

## The retroactive re-evaluation loop

This is the core innovation. When a regulation changes:

1. The scraper detects the change and creates a new `GuidelineVersion` with `affected_agent_tags` (e.g. `["transaction"]` for a FOIR limit change)
2. The retro-eval filter queries `audit_records` using a GIN-indexed array overlap query: only applications whose prior decision **actually invoked the changed agent** under the **prior guideline version** are selected
3. Only those applications are re-evaluated — not the entire portfolio
4. If the decision changes (`APPROVE → REJECT` or `REJECT → APPROVE`), the notification outbox queues alerts to both the applicant and the reviewer
5. Every re-evaluation creates its own audit record, building a complete provenance chain per application

This means the system can answer: *"Show me every applicant whose decision would change under the new FOIR rules"* — in under a minute, with full audit trail.

---

## DPDP compliance controls

All obligations are operational controls, not policy documents:

- **Consent gate**: hard middleware rejection if `dpdp_consent: true` is absent, consent version is stale, or consent timestamp is older than 24 hours
- **Data minimisation**: `AgentPayloadFilter` strips each agent's input to only the fields it needs — no agent ever sees PAN plaintext, Aadhaar numbers, or document content bytes
- **PAN handling**: HMAC-SHA256'd at ingestion; plaintext discarded; watchlist is pre-hashed with the same key
- **Storage limitation**: nightly Celery task enforces `data_retention_expires_at`, nulling `payload_encrypted` and PII fields while retaining the audit hash for non-repudiation
- **Breach response**: `break_glass` PostgreSQL procedure flags records, freezes retro-eval jobs, queues notifications, generates DPDP Board report

---

## Audit integrity

Every decision has an `audit_record` written synchronously before the HTTP response is returned:

```
agent_outputs_hash  = SHA-256(canonical JSON of all five AgentResults)
record_hmac         = HMAC-SHA256(hash + decision_id + guideline_version_id + written_at, SERVER_SECRET)
```

Verification: recompute both values, compare against stored values. Any tampering breaks the HMAC. The full encrypted payload is also uploaded to MinIO. Postgres is the source of truth.

---

## Technology stack (100% free / open-source)

| Layer | Technology |
|---|---|
| API | FastAPI 0.111+, Pydantic v2, Uvicorn |
| Pipeline | LangGraph (LangChain), PostgresSaver checkpointer |
| LLM | Ollama (Mistral 7B / LLaMA 3 8B) or Groq free tier |
| Embeddings | sentence-transformers `all-MiniLM-L6-v2` (CPU, 22MB) |
| Vector store | FAISS (CPU build, on-disk, atomic swap) |
| Database | PostgreSQL 16 (JSONB, GIN index, ACID) |
| Cache / broker | Redis 7 (Redis Stack) |
| Workers | Celery 5 + Celery Beat |
| Scraping | Scrapy 2.11 + Playwright (headless Chromium) |
| Object storage | MinIO (S3-compatible) |
| Observability | Prometheus + Grafana + structlog |
| Frontend (demo) | Next.js 14 App Router + shadcn/ui + Tailwind |
| Reverse proxy | Nginx |
| Containers | Docker + Docker Compose |
| Secrets | HashiCorp Vault (dev mode) |

---

## Repository structure

```
complianceloop/
├── api/                    # FastAPI app — routers, middleware, schemas
├── pipeline/               # LangGraph DAG — state, nodes, 5 agents, filters, prompts
├── audit/                  # Audit writer, hasher, verifier, MinIO uploader
├── retrieval/              # FAISS index manager, embedder, chunker, corpus extractors
├── scraper/                # Scrapy spiders, parser, delta detector, tagger, watchlist updater
├── retro_eval/             # Filter, batch runner, comparator, notifier, deduplicator
├── calibration/            # Calibration engine, feedback store, drift monitor
├── models/                 # SQLAlchemy ORM models (13 models)
├── db/                     # Alembic migrations (5 versions), seeds, demo data
├── workers/                # Celery app factory, queue definitions, Beat schedules
├── notifications/          # Email + webhook dispatcher, Jinja2 templates
├── dpdp/                   # Consent manager, retention enforcer, breach response
├── observability/          # Prometheus metrics, structlog config, tracing stub
├── security/               # AES-256-GCM encryption, HMAC utils, PAN handler, secrets
├── demo/                   # Guideline editor, SSE emitter, demo watcher
├── frontend/               # Next.js 14 demo dashboard (real-time, 3-panel)
├── infra/                  # Nginx, Prometheus, Grafana, Alertmanager, MinIO, Vault configs
├── scripts/                # Deploy, seed, index build, rotate secrets, break_glass
├── tests/                  # Integration + E2E tests (TestContainers)
├── docs/                   # Architecture docs, runbooks, ADRs, OpenAPI spec
├── docker-compose.yml
├── docker-compose.demo.yml
├── docker-compose.test.yml
├── Makefile
└── pyproject.toml
```

---

## Implementation plan (for Cursor / AI-assisted development)

This project is built in 24 sequential phases. Each phase produces files that subsequent phases import. **Do not skip phases.** Phases 1–8 are pure infrastructure with no domain logic — complete them before touching the pipeline.

### Phase dependency graph

```
Phase 1  (Foundation: Docker, requirements, env)
    │
Phase 2  (Security: encryption, HMAC, PAN)
    │
Phase 3  (Database: models, migrations)
    │
Phase 4  (Observability: Prometheus metrics, structlog)
    │
Phase 5  (Celery: worker app, queues, schedules)
    │
Phase 6  (DPDP: consent, retention, breach)
    │
Phase 7  (Retrieval: FAISS, embedder, chunker, corpus)
    │
Phase 8  (Audit: writer, hasher, verifier, S3 uploader)
    │
Phase 9  (Pipeline core: state, router, decision node — no agents yet)
    │
    ├── Phase 10a  (Document Agent)
    ├── Phase 10b  (Sanctions Agent)
    ├── Phase 10c  (Temporal Agent)
    ├── Phase 10d  (Transaction Agent)
    └── Phase 10e  (RAG Agent)
              │
         Phase 11  (Pipeline graph assembly + runner)
              │
         Phase 12  (Regulatory scraper: Scrapy spiders, parser, delta detector, tagger)
              │
         Phase 13  (Retro-eval loop: filter, batch runner, comparator, notifier)
              │
         Phase 14  (Calibration engine: feedback store, drift monitor)
              │
         Phase 15  (Notifications: email, webhook, templates)
              │
         Phase 16  (FastAPI: all routers, middleware, schemas)
              │
         Phase 17  (DB seeds: demo applicants, watchlist, guideline versions)
              │
         Phase 18  (Demo backend: guideline editor, SSE emitter)
              │
         Phase 19  (Frontend: Next.js dashboard, all components)
              │
         Phase 20  (Infrastructure: Nginx, Prometheus, Grafana configs)
              │
         Phase 21  (Scripts: deploy, rollback, seed, index, break_glass)
              │
         Phase 22  (Integration + E2E tests)
              │
         Phase 23  (CI/CD: GitHub Actions)
              │
         Phase 24  (ADRs + runbooks)
```

### What each phase produces

| Phase | Key outputs | Dependencies |
|---|---|---|
| 1 | Docker Compose stacks, pyproject.toml, all requirements files, Makefile, Dockerfile | Nothing |
| 2 | AES-256-GCM encryption, HMAC-SHA256 utilities, PAN HMAC handler, secrets loader | Phase 1 |
| 3 | All 13 SQLAlchemy models, 5 Alembic migrations, db session factory | Phases 1–2 |
| 4 | All Prometheus metric definitions, structlog processor chain | Phases 1–3 |
| 5 | Celery app factory, 4 queue definitions, Beat schedule, notification worker | Phases 1–4 |
| 6 | DPDP consent gate, nightly retention enforcer, break_glass procedure | Phases 1–5 |
| 7 | FAISS index manager with safe-swap, sentence-transformer embedder, text chunker, corpus extractors | Phases 1–4 |
| 8 | Audit writer (pre-response node), SHA-256 + HMAC hasher, verifier, MinIO uploader | Phases 2–4 |
| 9 | ComplianceState TypedDict, AgentResult types, router/decision/outcome nodes, BaseAgent ABC, all Jinja2 prompts | Phases 2–8 |
| 10a–e | Five specialist agents (each independently testable) | Phase 9 |
| 11 | build_graph() producing compiled StateGraph, PipelineRunner with sync/async modes | Phases 9–10 |
| 12 | Four Scrapy spiders, HTML/PDF parser, difflib delta detector, keyword+LLM tagger, watchlist updater | Phases 3–7 |
| 13 | GIN-indexed audit trail filter, chunked batch runner, decision comparator, notification writer | Phases 8–12 |
| 14 | Nightly calibration engine with threshold nudge + guard conditions, confidence drift monitor | Phases 3–5 |
| 15 | Email + webhook dispatcher, transactional outbox polling, 6 Jinja2 email templates | Phases 3–5 |
| 16 | Complete FastAPI application with all 8 routers, 5 middleware layers, all Pydantic schemas | Phases 2–15 |
| 17 | 25–30 synthetic demo applicants covering all pipeline paths, seeded watchlist, initial guideline params | Phase 3 |
| 18 | Demo guideline editor API, SSE event emitter, demo watcher connecting retro-eval to SSE | Phases 13–16 |
| 19 | Full Next.js dashboard: 3-panel live layout, all 8 components, SSE hook, typed API client | Phase 18 |
| 20 | All Nginx, Prometheus, Grafana, Alertmanager, MinIO, Vault configuration files | Phases 1–16 |
| 21 | 10 operational shell scripts: deploy, rollback, seed, index build, swap, rotate secrets, verify audit, break_glass, backup | All phases |
| 22 | 8 integration tests + 2 E2E tests using TestContainers for real Postgres + Redis | All phases |
| 23 | 4 GitHub Actions workflows: CI, CD, security scan, index health check | All phases |
| 24 | 4 ADRs + 5 runbooks | All phases |

---

## Key design decisions

### ADR-001 — LangGraph over custom orchestrator
LangGraph provides a typed state machine with a built-in PostgreSQL checkpointer, parallel node execution, conditional edges, and replay capability. Building equivalent infrastructure from scratch would require 2–3 weeks of work and produce less reliable behaviour. The deterministic DAG structure maps directly to the compliance decisioning problem.

### ADR-002 — FAISS over Chroma/Qdrant
FAISS runs entirely in-process with no server dependency. The index is a single file on disk that can be atomically swapped with an OS-level rename. For a system that needs zero-downtime index updates when regulations change, file-based atomic swap is simpler and more reliable than a remote vector database with its own availability concerns.

### ADR-003 — Audit write before API response
The audit record is written as the final LangGraph node, before the HTTP response is assembled. If MinIO upload fails, the Postgres record still exists. If the API worker crashes after writing Postgres but before responding, the evidence exists. The client may not get their response, but the compliance record does. This is a deliberate tradeoff: the regulated entity's audit obligation takes priority over API response latency.

### ADR-004 — DPDP controls in middleware, not decorators
Consent validation runs as ASGI middleware that intercepts the request before it reaches any router handler. This is not a decorator on each endpoint because a decorator can be accidentally omitted on a new endpoint. Middleware is unconditional — every POST to `/v1/applications` passes through it regardless of which developer wrote the router handler.

---

## Running locally (development)

### Prerequisites
- Docker 24+ and Docker Compose v2
- Python 3.11+
- Node.js 20+ (for frontend)
- Ollama installed locally (for LLM inference)

### 1. Clone and configure
```bash
git clone https://github.com/your-org/complianceloop.git
cd complianceloop
cp .env.example .env
# Edit .env — set POSTGRES_PASSWORD, REDIS_PASSWORD, MINIO_ROOT_PASSWORD, SERVER_HMAC_KEY, PAN_HMAC_KEY, AES_KEY
```

### 2. Pull the LLM model
```bash
ollama pull mistral:7b
```

### 3. Start the infrastructure stack
```bash
make dev
# Starts: postgres, redis, minio, prometheus, grafana, vault
```

### 4. Run database migrations and seed demo data
```bash
make migrate
make seed-demo
```

### 5. Build the FAISS index
```bash
make build-index
# Downloads initial RBI corpus from MinIO and builds the index
```

### 6. Start the API and workers
```bash
make run-api       # FastAPI on :8000
make run-worker    # Celery worker
make run-beat      # Celery Beat (scraper + calibration schedules)
```

### 7. Start the demo frontend
```bash
cd frontend && npm install && npm run dev
# Demo dashboard on :3000
```

### 8. Run tests
```bash
make test              # All tests
make test-unit         # Unit tests only (no Docker required)
make test-integration  # Integration tests (requires Docker)
```

---

## Running in production (Docker Compose)

```bash
# Production stack
docker compose up -d

# With demo environment
docker compose -f docker-compose.yml -f docker-compose.demo.yml up -d

# Check health
curl http://localhost:8000/health
```

---

## Makefile targets

| Target | What it does |
|---|---|
| `make dev` | Start infrastructure containers (no app) |
| `make migrate` | Run Alembic migrations |
| `make seed-demo` | Seed 25–30 synthetic applicants into demo DB |
| `make build-index` | Build FAISS index from corpus |
| `make swap-index` | Manually trigger safe index swap |
| `make run-api` | Start FastAPI with hot reload |
| `make run-worker` | Start Celery worker |
| `make run-beat` | Start Celery Beat scheduler |
| `make test` | Run full test suite |
| `make test-unit` | Run unit tests only |
| `make test-integration` | Run integration tests (TestContainers) |
| `make lint` | Run ruff + mypy |
| `make format` | Run black |
| `make deploy` | SSH deploy to production server |
| `make rollback` | Rollback production to previous image |
| `make rotate-secrets` | Rotate HMAC + AES keys with overlap window |
| `make verify-audit ID=<decision_id>` | Verify audit record integrity |
| `make break-glass APP=<application_id>` | Activate breach response procedure |

---

## API endpoints

| Endpoint | Method | Description |
|---|---|---|
| `POST /v1/applications` | POST | Submit loan application. Returns decision synchronously or `task_id` for polling. |
| `GET /v1/applications/{id}` | GET | Get application + latest decision + confidence. |
| `GET /v1/applications/{id}/decisions` | GET | Full decision history across all re-eval runs, with rationale chains. |
| `GET /v1/applications/{id}/audit` | GET | Audit record with hash and HMAC for integrity verification. |
| `POST /v1/reviewer/feedback` | POST | Submit reviewer outcome. Feeds calibration engine. |
| `GET /v1/reviewer/queue` | GET | Pending REVIEW cases for the reviewer dashboard. |
| `GET /v1/guidelines/current` | GET | Current active GuidelineVersion with parameters. |
| `POST /v1/guidelines/promote/{id}` | POST | Promote pending version to active (compliance_admin role). |
| `GET /v1/calibration/status` | GET | Current thresholds + last adjustment + 7-day confidence stats. |
| `GET /demo/events` | GET (SSE) | Server-Sent Events stream for live demo dashboard. |
| `POST /demo/guidelines/edit` | POST | Modify guideline parameters in demo (API-key gated). |
| `GET /health` | GET | Service health: DB, Redis, FAISS index age. |

Full OpenAPI spec available at `/docs` (Swagger UI) or `/redoc` when the API is running.

---

## Observability

- **Grafana**: http://localhost:3001 (admin/admin on first run)
  - Compliance Operations Overview
  - Pipeline Health (per-agent latency heatmaps)
  - Regulatory Intelligence (scraper runs, delta detections)
  - Calibration Tracker (threshold history, confidence drift)
- **Prometheus**: http://localhost:9090
- **Structured logs**: JSON to stdout, parseable by Loki or any log aggregator

---

## Environment variables

All variables are documented in `.env.example`. Critical variables:

| Variable | Purpose |
|---|---|
| `POSTGRES_DSN` | PostgreSQL connection string |
| `REDIS_URL` | Redis connection URL |
| `MINIO_ENDPOINT` | MinIO endpoint (default: localhost:9000) |
| `SERVER_HMAC_KEY` | 256-bit hex key for audit record HMAC signing |
| `PAN_HMAC_KEY` | 256-bit hex key for PAN HMAC (separate from audit key) |
| `AES_KEY` | 256-bit hex key for payload_encrypted AES-256-GCM |
| `OLLAMA_BASE_URL` | LLM inference endpoint (default: http://localhost:11434) |
| `LLM_MODEL` | Model name (default: mistral:7b) |
| `DEMO_API_KEY` | API key for demo guideline editor endpoint |
| `SENDGRID_API_KEY` | SendGrid free-tier key for email notifications |
| `SCRAPER_INTERVAL_HOURS` | How often the RBI scraper runs (default: 6) |
| `RETRO_EVAL_RATE_PER_MIN` | Max re-evals per minute (default: 50) |
| `DEMO_MODE` | Set to `true` to enable demo-specific behaviours |

---

## Security notes

- PAN is HMAC-SHA256'd at ingestion. Plaintext PAN never touches the database.
- All application payloads are AES-256-GCM encrypted at rest in PostgreSQL.
- Audit records are HMAC-signed. Any tampering is detectable.
- The demo environment uses a completely separate PostgreSQL instance. Demo data and production data share no storage.
- API keys are stored as bcrypt hashes in the `api_keys` table.
- TLS is terminated at Nginx. All inter-container communication is on a private Docker network.

---

## Compliance references

This system is designed around:

- **RBI Master Direction — NBFC Directions, 2016** (as amended through 2025)
- **RBI Master Direction on KYC, 2016** (as amended)
- **RBI Guidelines on Digital Lending, 2022**
- **RBI Scale-Based Regulation Framework for NBFCs, 2021**
- **PMLA Rules, 2005** (AML/KYC)
- **DPDP Act, 2023** and draft DPDP Rules, 2025
- **FATF Recommendations** (sanctions screening methodology)

Regulatory content is retrieved from public sources and is not legal advice. NBFCs should validate the system's rule parameters against their specific regulatory obligations with qualified legal counsel.

---

## Contributing

See `docs/runbooks/` for operational procedures. Architecture decisions are documented in `docs/decisions/`. Before making significant changes to agent logic or threshold computation, create an ADR in `docs/decisions/`.

---

## License

Proprietary. See `LICENSE` for terms.
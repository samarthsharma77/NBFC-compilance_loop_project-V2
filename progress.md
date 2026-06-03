This is the implentation plan things will go according to it:
(
Implementation Path/Plan —
The order matters. Each step produces files that the next step imports. Never skip a step.

PHASE 1 — Foundation (ask me all at once)
Files:
pyproject.toml
requirements/base.txt
requirements/api.txt
requirements/pipeline.txt
requirements/scraper.txt
requirements/worker.txt
requirements/dev.txt
requirements/security.txt
.env.example
Makefile
Dockerfile
docker-compose.yml
docker-compose.demo.yml
docker-compose.test.yml

PHASE 2 — Security & Encryption primitives
Files:
security/__init__.py
security/encryption.py
security/hmac_utils.py
security/pan_handler.py
security/secrets_loader.py
security/tests/__init__.py
security/tests/test_encryption.py
security/tests/test_pan_handler.py

PHASE 3 — Database models + migrations
Files:
models/__init__.py
models/base.py
models/application.py
models/decision.py
models/audit_record.py
models/guideline_version.py
models/reviewer.py
models/notification_outbox.py
models/calibration_config.py
models/calibration_stats.py
models/consent_version.py
models/retention_event.py
models/api_key.py
db/__init__.py
db/session.py
db/engine.py
db/migrations/env.py
db/migrations/script.py.mako
db/migrations/versions/0001_initial_schema.py
db/migrations/versions/0002_add_gin_index_agent_tags.py
db/migrations/versions/0003_add_calibration_tables.py
db/migrations/versions/0004_add_consent_versions.py
db/migrations/versions/0005_add_retention_events.py

PHASE 4 — Observability & Logging
Files:
observability/__init__.py
observability/metrics.py
observability/logging_config.py
observability/tracing.py
observability/tests/__init__.py
observability/tests/test_metrics.py

PHASE 5 — Celery workers & queue definitions
Files:
workers/__init__.py
workers/celery_app.py
workers/queues.py
workers/schedules.py
workers/notification_worker.py

PHASE 6 — DPDP compliance controls
Files:
dpdp/__init__.py
dpdp/consent_manager.py
dpdp/retention_enforcer.py
dpdp/breach_response.py
dpdp/data_subject_handler.py
dpdp/tests/__init__.py
dpdp/tests/test_consent_manager.py
dpdp/tests/test_retention_enforcer.py
dpdp/tests/test_breach_response.py

PHASE 7 — Retrieval layer (FAISS + embeddings)
Files:
retrieval/__init__.py
retrieval/embedder.py
retrieval/chunker.py
retrieval/corpus/pdf_extractor.py
retrieval/corpus/html_extractor.py
retrieval/corpus/preprocessor.py
retrieval/index_manager.py
retrieval/retriever.py
retrieval/golden_test_set.json
retrieval/tests/__init__.py
retrieval/tests/test_embedder.py
retrieval/tests/test_chunker.py
retrieval/tests/test_index_manager.py
retrieval/tests/test_retriever.py

PHASE 8 — Audit system
Files:
audit/__init__.py
audit/writer.py
audit/hasher.py
audit/verifier.py
audit/s3_uploader.py
audit/tests/__init__.py
audit/tests/test_writer.py
audit/tests/test_hasher.py
audit/tests/test_verifier.py

PHASE 9 — LangGraph pipeline state + nodes (no agents yet)
Files:
pipeline/__init__.py
pipeline/state.py
pipeline/filters/payload_filter.py
pipeline/nodes/__init__.py
pipeline/nodes/router_node.py
pipeline/nodes/decision_node.py
pipeline/nodes/outcome_router.py
pipeline/agents/__init__.py
pipeline/agents/base_agent.py
pipeline/prompts/rag_system.j2
pipeline/prompts/rag_synthesis.j2
pipeline/prompts/tagger_classification.j2
pipeline/tests/__init__.py
pipeline/tests/conftest.py
pipeline/tests/fixtures/clean_approve_state.json
pipeline/tests/fixtures/sanctions_fail_state.json
pipeline/tests/fixtures/foir_breach_state.json
pipeline/tests/fixtures/expired_kyc_state.json
pipeline/tests/fixtures/all_warn_state.json

PHASE 10 — The five specialist agents (ask each separately — they are large)
pipeline/agents/document_agent.py
pipeline/tests/test_document_agent.py
pipeline/agents/sanctions_agent.py
pipeline/tests/test_sanctions_agent.py
pipeline/agents/temporal_agent.py
pipeline/tests/test_temporal_agent.py
pipeline/agents/transaction_agent.py
pipeline/tests/test_transaction_agent.py
pipeline/agents/rag_agent.py
pipeline/tests/test_rag_agent.py

PHASE 11 — Pipeline graph assembly + runner
Files:
pipeline/graph.py
pipeline/runner.py
pipeline/tests/test_graph.py
pipeline/tests/test_router_node.py
pipeline/tests/test_decision_node.py
pipeline/tests/test_payload_filter.py

PHASE 12 — Regulatory scraper
Files:
scraper/__init__.py
scraper/scrapy_project/scrapy.cfg
scraper/scrapy_project/compliance_scraper/__init__.py
scraper/scrapy_project/compliance_scraper/settings.py
scraper/scrapy_project/compliance_scraper/items.py
scraper/scrapy_project/compliance_scraper/pipelines.py
scraper/scrapy_project/compliance_scraper/middlewares.py
scraper/scrapy_project/compliance_scraper/spiders/__init__.py
scraper/scrapy_project/compliance_scraper/spiders/rbi_circulars.py
scraper/scrapy_project/compliance_scraper/spiders/rbi_kyc.py
scraper/scrapy_project/compliance_scraper/spiders/dpdp_portal.py
scraper/scrapy_project/compliance_scraper/spiders/mca_notifications.py
scraper/parser.py
scraper/delta_detector.py
scraper/tagger.py
scraper/watchlist_updater.py
scraper/tasks.py
scraper/tests/__init__.py
scraper/tests/test_parser.py
scraper/tests/test_delta_detector.py
scraper/tests/test_tagger.py
scraper/tests/fixtures/rbi_circular_sample.html
scraper/tests/fixtures/rbi_circular_updated.html
scraper/tests/fixtures/dpdp_rules_sample.html

PHASE 13 — Retro-evaluation loop
Files:
retro_eval/__init__.py
retro_eval/filter.py
retro_eval/batch_runner.py
retro_eval/comparator.py
retro_eval/notifier.py
retro_eval/deduplicator.py
retro_eval/tasks.py
retro_eval/tests/__init__.py
retro_eval/tests/test_filter.py
retro_eval/tests/test_comparator.py
retro_eval/tests/test_notifier.py
retro_eval/tests/test_deduplicator.py

PHASE 14 — Calibration engine
Files:
calibration/__init__.py
calibration/engine.py
calibration/feedback_store.py
calibration/drift_monitor.py
calibration/tasks.py
calibration/tests/__init__.py
calibration/tests/test_engine.py
calibration/tests/test_drift_monitor.py
calibration/tests/fixtures/reviewer_feedback_sample.json

PHASE 15 — Notification system
Files:
notifications/__init__.py
notifications/dispatcher.py
notifications/email_sender.py
notifications/webhook_sender.py
notifications/templates/decision_change_applicant.html
notifications/templates/decision_change_applicant.txt
notifications/templates/review_assigned.html
notifications/templates/review_assigned.txt
notifications/templates/breach_alert.html
notifications/templates/breach_alert.txt
notifications/tests/__init__.py
notifications/tests/test_dispatcher.py
notifications/tests/test_email_sender.py

PHASE 16 — FastAPI application
Files:
api/__init__.py
api/main.py
api/config.py
api/dependencies.py
api/middleware/__init__.py
api/middleware/dpdp_consent.py
api/middleware/rate_limit.py
api/middleware/correlation_id.py
api/middleware/request_logging.py
api/middleware/api_key_auth.py
api/schemas/__init__.py
api/schemas/application.py
api/schemas/decision.py
api/schemas/audit.py
api/schemas/guideline.py
api/schemas/reviewer.py
api/schemas/calibration.py
api/schemas/demo.py
api/schemas/errors.py
api/routers/__init__.py
api/routers/applications.py
api/routers/decisions.py
api/routers/audit.py
api/routers/guidelines.py
api/routers/reviewer.py
api/routers/calibration.py
api/routers/health.py
api/routers/demo.py
api/tests/__init__.py
api/tests/conftest.py
api/tests/test_applications.py
api/tests/test_audit.py
api/tests/test_guidelines.py
api/tests/test_dpdp_middleware.py
api/tests/test_rate_limit.py
api/tests/test_health.py

PHASE 17 — Database seeds
Files:
db/seeds/__init__.py
db/seeds/demo_seed.py
db/seeds/demo_applicants.json
db/seeds/demo_watchlist.json
db/seeds/demo_guideline_versions.json

PHASE 18 — Demo backend
Files:
demo/__init__.py
demo/guideline_editor.py
demo/sse_emitter.py
demo/watch.py
demo/tests/__init__.py
demo/tests/test_guideline_editor.py
demo/tests/test_sse_emitter.py

PHASE 19 — Frontend (Next.js demo dashboard)
Files:
frontend/package.json
frontend/next.config.js
frontend/tailwind.config.js
frontend/tsconfig.json
frontend/app/layout.tsx
frontend/app/page.tsx
frontend/app/globals.css
frontend/app/demo/page.tsx
frontend/app/demo/layout.tsx
frontend/app/demo/components/ApplicantTable.tsx
frontend/app/demo/components/EventFeed.tsx
frontend/app/demo/components/StatsBar.tsx
frontend/app/demo/components/GuidelineEditor.tsx
frontend/app/demo/components/DecisionBadge.tsx
frontend/app/demo/components/ConfidenceBar.tsx
frontend/app/demo/components/AuditTrailDrawer.tsx
frontend/app/demo/components/NotificationToast.tsx
frontend/app/api/sse/route.ts
frontend/app/lib/api-client.ts
frontend/app/lib/use-sse.ts
frontend/app/lib/types.ts
frontend/Dockerfile

PHASE 20 — Infrastructure configs
Files:
infra/nginx/nginx.conf
infra/nginx/sites/api.conf
infra/nginx/sites/demo.conf
infra/prometheus/prometheus.yml
infra/prometheus/alert_rules/pipeline.yml
infra/prometheus/alert_rules/scraper.yml
infra/prometheus/alert_rules/calibration.yml
infra/prometheus/alert_rules/infrastructure.yml
infra/grafana/grafana.ini
infra/grafana/provisioning/datasources/prometheus.yaml
infra/grafana/provisioning/dashboards/dashboard_provider.yaml
infra/grafana/dashboards/compliance_operations.json
infra/grafana/dashboards/pipeline_health.json
infra/grafana/dashboards/regulatory_intelligence.json
infra/grafana/dashboards/calibration_tracker.json
infra/alertmanager/alertmanager.yml
infra/minio/init_buckets.sh
infra/vault/vault.hcl
infra/vault/init_secrets.sh

PHASE 21 — Scripts
Files:
scripts/deploy.sh
scripts/rollback.sh
scripts/seed_demo.sh
scripts/build_faiss_index.sh
scripts/swap_faiss_index.sh
scripts/rotate_secrets.sh
scripts/verify_audit_record.sh
scripts/break_glass.sh
scripts/pg_backup.sh
scripts/generate_api_key.sh

PHASE 22 — Integration + E2E tests
Files:
tests/__init__.py
tests/conftest.py
tests/integration/test_full_pipeline_approve.py
tests/integration/test_full_pipeline_sanctions.py
tests/integration/test_full_pipeline_foir.py
tests/integration/test_retro_eval_flow.py
tests/integration/test_faiss_index_swap.py
tests/integration/test_audit_integrity.py
tests/integration/test_dpdp_retention.py
tests/integration/test_calibration_cycle.py
tests/e2e/test_api_application_lifecycle.py
tests/e2e/test_demo_sse_flow.py

PHASE 23 — CI/CD + GitHub Actions
Files:
.github/workflows/ci.yml
.github/workflows/cd.yml
.github/workflows/security-scan.yml
.github/workflows/index-health-check.yml
.github/PULL_REQUEST_TEMPLATE.md
.github/ISSUE_TEMPLATE/bug_report.md
.github/ISSUE_TEMPLATE/compliance_gap.md
.github/CODEOWNERS

PHASE 24 — Documentation 
Files:
docs/decisions/ADR-001-langgraph-over-custom.md
docs/decisions/ADR-002-faiss-over-chroma.md
docs/decisions/ADR-003-audit-before-response.md
docs/decisions/ADR-004-dpdp-middleware-not-decorator.md
docs/runbooks/incident_response.md
docs/runbooks/breach_response.md
docs/runbooks/faiss_index_rollback.md
docs/runbooks/calibration_manual_override.md
docs/runbooks/regulator_audit_response.md
)

progress report:

Date:02/06/2026
completed : phase 1 files 
due : phase 2 - phase 24

Date:02/06/2026
completed : phase 1 and 2 files 
due : phase 3 - phase 24

Date:03/06/2026
completed : phase 1-3 files 
due : phase 4 - phase 24
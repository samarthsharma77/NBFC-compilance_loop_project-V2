"""Initial schema — all core tables

Creates:
  - api_keys
  - consent_versions
  - guideline_versions
  - reviewers
  - applications
  - decisions
  - audit_records
  - reviewer_feedback
  - notification_outbox

All ENUM types are created before their tables.
UUID extension is enabled first.
All indexes defined inline with tables.

Revision ID: 0001
Revises: None
Create Date: 2026-06-01 00:00:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers
revision: str = "0001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── Enable PostgreSQL extensions ──────────────────────────────────────────
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')   # gen_random_uuid()
    op.execute('CREATE EXTENSION IF NOT EXISTS "pg_trgm"')    # fuzzy text search (future)

    # ── Create ENUM types ─────────────────────────────────────────────────────
    op.execute("""
        CREATE TYPE decision_outcome_enum AS ENUM ('APPROVE', 'REVIEW', 'REJECT')
    """)
    op.execute("""
        CREATE TYPE reviewer_role_enum AS ENUM (
            'REVIEWER', 'SENIOR_REVIEWER', 'COMPLIANCE_ADMIN'
        )
    """)
    op.execute("""
        CREATE TYPE reviewer_outcome_enum AS ENUM (
            'CONFIRM_APPROVE', 'CONFIRM_REJECT',
            'OVERRIDE_APPROVE', 'OVERRIDE_REJECT', 'ESCALATE'
        )
    """)
    op.execute("""
        CREATE TYPE notification_type_enum AS ENUM (
            'DECISION_CHANGE', 'REVIEW_ASSIGNED', 'BREACH_ALERT'
        )
    """)
    op.execute("""
        CREATE TYPE notification_channel_enum AS ENUM ('EMAIL', 'WEBHOOK')
    """)
    op.execute("""
        CREATE TYPE notification_status_enum AS ENUM (
            'PENDING', 'SENT', 'FAILED', 'SUPPRESSED'
        )
    """)

    # ── api_keys ──────────────────────────────────────────────────────────────
    op.create_table(
        "api_keys",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("key_prefix", sa.String(8), nullable=False),
        sa.Column("key_hash", sa.String(60), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("scopes", postgresql.ARRAY(sa.String(50)),
                  nullable=False, server_default="{}"),
        sa.Column("is_active", sa.Boolean(), nullable=False,
                  server_default=sa.text("true")),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("use_count", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("created_by", sa.String(100), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_by", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="Hashed API keys for API authentication",
    )
    op.create_index("ix_api_keys_key_prefix", "api_keys", ["key_prefix"])

    # ── consent_versions ──────────────────────────────────────────────────────
    op.create_table(
        "consent_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("version_id", sa.String(50), nullable=False, unique=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("consent_text", sa.Text(), nullable=False),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("superseded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("change_summary", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="DPDP consent form versions",
    )
    op.create_index("ix_consent_versions_version_id", "consent_versions",
                    ["version_id"], unique=True)
    op.create_index(
        "ix_consent_versions_active", "consent_versions", ["is_active"],
        unique=True,
        postgresql_where=sa.text("is_active = true"),
    )

    # ── guideline_versions ────────────────────────────────────────────────────
    op.create_table(
        "guideline_versions",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("source_url", sa.Text(), nullable=False),
        sa.Column("circular_reference", sa.String(200), nullable=False),
        sa.Column("title", sa.Text(), nullable=True),
        sa.Column("effective_date", sa.Date(), nullable=True),
        sa.Column("sunset_date", sa.Date(), nullable=True),
        sa.Column("scraped_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("content_hash", sa.String(64), nullable=False),
        sa.Column("diff_summary", sa.Text(), nullable=True),
        sa.Column("affected_agent_tags",
                  postgresql.ARRAY(sa.String(50)),
                  nullable=False, server_default="{}"),
        sa.Column("parameters", postgresql.JSONB(), nullable=False,
                  server_default=sa.text("'{}'")),
        sa.Column("is_active", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("promoted_by", sa.String(100), nullable=True),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("raw_content_s3_key", sa.String(500), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="Versioned regulatory guidelines scraped from RBI and DPDP sources",
    )
    op.create_index("ix_guideline_versions_circular_ref",
                    "guideline_versions", ["circular_reference"])
    op.create_index("ix_guideline_versions_is_demo",
                    "guideline_versions", ["is_demo"])
    # Partial unique: only one active version per circular per environment
    op.create_index(
        "ix_guideline_versions_active_circular",
        "guideline_versions",
        ["circular_reference", "is_demo"],
        unique=True,
        postgresql_where=sa.text("is_active = true"),
    )

    # ── reviewers ─────────────────────────────────────────────────────────────
    op.create_table(
        "reviewers",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("full_name", sa.String(255), nullable=False),
        sa.Column("role",
                  postgresql.ENUM("REVIEWER", "SENIOR_REVIEWER", "COMPLIANCE_ADMIN",
                                  name="reviewer_role_enum", create_type=False),
                  nullable=False, server_default="REVIEWER"),
        sa.Column("is_active", sa.Boolean(), nullable=False,
                  server_default=sa.text("true")),
        sa.Column("notification_webhook_url", sa.String(500), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="Human compliance reviewers",
    )
    op.create_index("ix_reviewers_email", "reviewers", ["email"], unique=True)

    # ── applications ──────────────────────────────────────────────────────────
    op.create_table(
        "applications",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("applicant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("applicant_name", sa.String(255), nullable=False),
        sa.Column("pan_hmac", sa.String(64), nullable=False),
        sa.Column("pan_format_valid", sa.Boolean(), nullable=False,
                  server_default=sa.text("true")),
        sa.Column("loan_amount_requested", sa.Numeric(15, 2), nullable=False),
        sa.Column("loan_tenure_months", sa.Integer(), nullable=False),
        sa.Column("loan_purpose", sa.String(100), nullable=False),
        sa.Column("declared_income", sa.Numeric(15, 2), nullable=False),
        sa.Column("declared_obligations", sa.Numeric(15, 2), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("collateral_value", sa.Numeric(15, 2), nullable=True),
        sa.Column("city_tier", sa.String(10), nullable=True),
        sa.Column("remote_onboarding", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("applicant_risk_category", sa.String(20), nullable=False,
                  server_default=sa.text("'LOW'")),
        sa.Column("guideline_version_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("guideline_versions.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("payload_encrypted", sa.LargeBinary(), nullable=True),
        sa.Column("dpdp_consent_given", sa.Boolean(), nullable=False),
        sa.Column("dpdp_consent_version", sa.String(50), nullable=False),
        sa.Column("dpdp_consent_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("data_retention_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retention_wiped", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("retention_wiped_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip_hash", sa.String(64), nullable=True),
        sa.Column("api_key_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("api_keys.id", ondelete="SET NULL"), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="Loan applications submitted to the compliance pipeline",
    )
    op.create_index("ix_applications_applicant_id", "applications", ["applicant_id"])
    op.create_index("ix_applications_pan_hmac", "applications", ["pan_hmac"])
    op.create_index("ix_applications_submitted_at", "applications", ["submitted_at"])
    op.create_index("ix_applications_loan_purpose", "applications", ["loan_purpose"])
    op.create_index("ix_applications_is_demo", "applications", ["is_demo"])
    op.create_index("ix_applications_guideline_version_id", "applications",
                    ["guideline_version_id"])
    op.create_index(
        "ix_applications_retention_wipe", "applications",
        ["data_retention_expires_at", "retention_wiped"],
    )
    op.create_index(
        "ix_applications_active_demo", "applications",
        ["is_demo", "submitted_at"],
        postgresql_where=sa.text("retention_wiped = false"),
    )

    # ── decisions ─────────────────────────────────────────────────────────────
    op.create_table(
        "decisions",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("application_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("applications.id", ondelete="CASCADE"),
                  nullable=False),
        sa.Column("guideline_version_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("guideline_versions.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("previous_decision_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("decisions.id", ondelete="SET NULL"),
                  nullable=True),
        sa.Column("run_number", sa.Integer(), nullable=False,
                  server_default=sa.text("1")),
        sa.Column("is_retro_eval", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("outcome",
                  postgresql.ENUM("APPROVE", "REVIEW", "REJECT",
                                  name="decision_outcome_enum", create_type=False),
                  nullable=False),
        sa.Column("confidence", sa.Numeric(5, 4), nullable=False),
        sa.Column("composite_score", sa.Numeric(5, 4), nullable=False),
        sa.Column("agent_outputs", postgresql.JSONB(), nullable=False),
        sa.Column("outcome_signals", postgresql.JSONB(), nullable=False),
        sa.Column("rationale_chain", postgresql.JSONB(), nullable=False),
        sa.Column("pipeline_duration_ms", sa.Integer(), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="Pipeline run results — one row per evaluation",
    )
    op.create_index("ix_decisions_application_id", "decisions", ["application_id"])
    op.create_index("ix_decisions_outcome", "decisions", ["outcome"])
    op.create_index("ix_decisions_guideline_version", "decisions",
                    ["guideline_version_id", "outcome"])
    op.create_index("ix_decisions_application_run", "decisions",
                    ["application_id", "run_number"])
    op.create_index("ix_decisions_is_demo", "decisions", ["is_demo", "created_at"])
    op.create_index(
        "ix_decisions_review_outcomes", "decisions",
        ["outcome", "created_at"],
        postgresql_where=sa.text("outcome = 'REVIEW'"),
    )

    # ── audit_records ─────────────────────────────────────────────────────────
    op.create_table(
        "audit_records",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("decision_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("decisions.id", ondelete="RESTRICT"),
                  nullable=False, unique=True),
        sa.Column("application_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("applications.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("guideline_version_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("guideline_versions.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("affected_agent_tags",
                  postgresql.ARRAY(sa.String(50)),
                  nullable=False, server_default="{}"),
        sa.Column("agent_outputs_hash", sa.String(64), nullable=False),
        sa.Column("record_hmac", sa.String(64), nullable=False),
        sa.Column("payload_s3_key", sa.String(500), nullable=True),
        sa.Column("payload_s3_uploaded", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("written_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("breach_flag", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("breach_flagged_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        comment="Immutable tamper-evident audit ledger",
    )
    op.create_index("ix_audit_records_application_id",
                    "audit_records", ["application_id"])
    op.create_index("ix_audit_records_written_at", "audit_records", ["written_at"])
    op.create_index("ix_audit_records_version_tags", "audit_records",
                    ["guideline_version_id", "application_id"])
    # GIN index for affected_agent_tags array overlap queries (retro-eval filter)
    op.create_index(
        "ix_audit_records_agent_tags_gin",
        "audit_records",
        ["affected_agent_tags"],
        postgresql_using="gin",
    )
    op.create_index("uq_audit_records_decision_id",
                    "audit_records", ["decision_id"], unique=True)

    # ── reviewer_feedback ─────────────────────────────────────────────────────
    op.create_table(
        "reviewer_feedback",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("decision_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("decisions.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("reviewer_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("reviewers.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("reviewer_outcome",
                  postgresql.ENUM("CONFIRM_APPROVE", "CONFIRM_REJECT",
                                  "OVERRIDE_APPROVE", "OVERRIDE_REJECT", "ESCALATE",
                                  name="reviewer_outcome_enum", create_type=False),
                  nullable=False),
        sa.Column("reviewer_notes", sa.Text(), nullable=True),
        sa.Column("pipeline_confidence_at_review",
                  sa.Numeric(5, 4), nullable=True),
        sa.Column("review_duration_seconds", sa.Integer(), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="Reviewer outcomes on REVIEW decisions",
    )
    op.create_index("ix_reviewer_feedback_decision_id",
                    "reviewer_feedback", ["decision_id"])
    op.create_index("ix_reviewer_feedback_reviewer_id",
                    "reviewer_feedback", ["reviewer_id"])
    op.create_index("ix_reviewer_feedback_created_at",
                    "reviewer_feedback", ["created_at"])
    op.create_index("ix_reviewer_feedback_outcome",
                    "reviewer_feedback", ["reviewer_outcome"])

    # ── notification_outbox ───────────────────────────────────────────────────
    op.create_table(
        "notification_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("notification_type",
                  postgresql.ENUM("DECISION_CHANGE", "REVIEW_ASSIGNED", "BREACH_ALERT",
                                  name="notification_type_enum", create_type=False),
                  nullable=False),
        sa.Column("channel",
                  postgresql.ENUM("EMAIL", "WEBHOOK",
                                  name="notification_channel_enum", create_type=False),
                  nullable=False),
        sa.Column("recipient_application_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("applications.id", ondelete="SET NULL"), nullable=True),
        sa.Column("recipient_reviewer_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("reviewers.id", ondelete="SET NULL"), nullable=True),
        sa.Column("recipient_email", sa.String(255), nullable=True),
        sa.Column("recipient_webhook_url", sa.String(500), nullable=True),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("status",
                  postgresql.ENUM("PENDING", "SENT", "FAILED", "SUPPRESSED",
                                  name="notification_status_enum", create_type=False),
                  nullable=False, server_default=sa.text("'PENDING'")),
        sa.Column("retry_count", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("max_retries", sa.Integer(), nullable=False,
                  server_default=sa.text("3")),
        sa.Column("next_retry_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("failure_reason", sa.String(500), nullable=True),
        sa.Column("is_demo", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="Transactional outbox for reliable notification delivery",
    )
    op.create_index("ix_notification_outbox_status",
                    "notification_outbox", ["status"])
    op.create_index("ix_notification_outbox_application",
                    "notification_outbox", ["recipient_application_id"])
    op.create_index(
        "ix_notification_outbox_pending",
        "notification_outbox",
        ["status", "next_retry_at"],
        postgresql_where=sa.text("status = 'PENDING'"),
    )


def downgrade() -> None:
    # Drop tables in reverse FK dependency order
    op.drop_table("notification_outbox")
    op.drop_table("reviewer_feedback")
    op.drop_table("audit_records")
    op.drop_table("decisions")
    op.drop_table("applications")
    op.drop_table("reviewers")
    op.drop_table("guideline_versions")
    op.drop_table("consent_versions")
    op.drop_table("api_keys")

    # Drop ENUM types
    op.execute("DROP TYPE IF EXISTS notification_status_enum")
    op.execute("DROP TYPE IF EXISTS notification_channel_enum")
    op.execute("DROP TYPE IF EXISTS notification_type_enum")
    op.execute("DROP TYPE IF EXISTS reviewer_outcome_enum")
    op.execute("DROP TYPE IF EXISTS reviewer_role_enum")
    op.execute("DROP TYPE IF EXISTS decision_outcome_enum")
"""Add calibration_config and calibration_stats tables

Creates the two tables used by the calibration engine:
  - calibration_config: versioned decision threshold configuration
  - calibration_stats: nightly run statistics for Grafana / Prometheus

Also inserts the default initial calibration config row so the pipeline
has something to read on first run.

Revision ID: 0003
Revises: 0002
Create Date: 2026-06-01 00:02:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0003"
down_revision: Union[str, None] = "0002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── calibration_config ────────────────────────────────────────────────────
    op.create_table(
        "calibration_config",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("approve_threshold", sa.Float(), nullable=False,
                  server_default=sa.text("0.82")),
        sa.Column("review_threshold", sa.Float(), nullable=False,
                  server_default=sa.text("0.60")),
        sa.Column("weight_document", sa.Float(), nullable=False,
                  server_default=sa.text("0.30")),
        sa.Column("weight_sanctions", sa.Float(), nullable=False,
                  server_default=sa.text("0.25")),
        sa.Column("weight_temporal", sa.Float(), nullable=False,
                  server_default=sa.text("0.20")),
        sa.Column("weight_transaction", sa.Float(), nullable=False,
                  server_default=sa.text("0.20")),
        sa.Column("weight_rag", sa.Float(), nullable=False,
                  server_default=sa.text("0.05")),
        sa.Column("is_active", sa.Boolean(), nullable=False,
                  server_default=sa.text("false")),
        sa.Column("version_number", sa.Integer(), nullable=False,
                  server_default=sa.text("1")),
        sa.Column("adjustment_reason", sa.Text(), nullable=True),
        sa.Column("samples_analysed", sa.Integer(), nullable=True),
        sa.Column("previous_config_id", sa.String(36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="Versioned decision threshold configuration — updated by calibration engine",
    )
    # Partial unique: only one active config
    op.create_index(
        "ix_calibration_config_active",
        "calibration_config",
        ["is_active"],
        unique=True,
        postgresql_where=sa.text("is_active = true"),
    )

    # ── calibration_stats ─────────────────────────────────────────────────────
    op.create_table(
        "calibration_stats",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("total_decisions_7d", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("approve_count_7d", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("review_count_7d", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("reject_count_7d", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("confidence_mean_7d", sa.Float(), nullable=True),
        sa.Column("confidence_stddev_7d", sa.Float(), nullable=True),
        sa.Column("confidence_p50_7d", sa.Float(), nullable=True),
        sa.Column("confidence_p95_7d", sa.Float(), nullable=True),
        sa.Column("override_rate_band_060_065", sa.Float(), nullable=True),
        sa.Column("override_rate_band_065_070", sa.Float(), nullable=True),
        sa.Column("override_rate_band_070_075", sa.Float(), nullable=True),
        sa.Column("override_rate_band_075_080", sa.Float(), nullable=True),
        sa.Column("override_rate_band_080_085", sa.Float(), nullable=True),
        sa.Column("total_feedback_30d", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("override_approve_30d", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("override_reject_30d", sa.Integer(), nullable=False,
                  server_default=sa.text("0")),
        sa.Column("approve_threshold_snapshot", sa.Float(), nullable=True),
        sa.Column("review_threshold_snapshot", sa.Float(), nullable=True),
        sa.Column("run_duration_seconds", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        comment="Nightly calibration run statistics",
    )
    op.create_index("ix_calibration_stats_created_at",
                    "calibration_stats", ["created_at"])

    # ── Seed default calibration config ───────────────────────────────────────
    # Insert the initial active config so pipeline has defaults on first run
    op.execute("""
        INSERT INTO calibration_config (
            id,
            approve_threshold, review_threshold,
            weight_document, weight_sanctions, weight_temporal,
            weight_transaction, weight_rag,
            is_active, version_number,
            adjustment_reason,
            created_at, updated_at
        ) VALUES (
            gen_random_uuid(),
            0.82, 0.60,
            0.30, 0.25, 0.20, 0.20, 0.05,
            true, 1,
            'Initial default configuration — set at schema creation',
            now(), now()
        )
    """)


def downgrade() -> None:
    op.drop_table("calibration_stats")
    op.drop_table("calibration_config")
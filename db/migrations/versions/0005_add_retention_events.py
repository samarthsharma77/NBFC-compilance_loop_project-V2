"""Add retention_events table and break_glass stored procedure

Creates:
  - retention_events table: audit log of DPDP PII wipe events
  - break_glass() stored procedure: DPDP breach response
  - updated_at trigger function: auto-updates updated_at on all tables

The break_glass() procedure:
  1. Sets breach_flag=True on audit_records for given application_id
  2. Records breach_flagged_at timestamp
  3. Inserts BREACH_ALERT notifications into notification_outbox
  This is callable as: SELECT break_glass('<application_id>');
  Or for a time range: SELECT break_glass_range('<start>', '<end>');

The trigger function ensures updated_at is always current, even for
direct SQL updates (e.g. from scripts or admin operations).

Revision ID: 0005
Revises: 0004
Create Date: 2026-06-01 00:04:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "0005"
down_revision: Union[str, None] = "0004"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── retention_events ──────────────────────────────────────────────────────
    op.create_table(
        "retention_events",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"),
                  nullable=False, primary_key=True),
        sa.Column("application_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("applications.id", ondelete="RESTRICT"),
                  nullable=False),
        sa.Column("wiped_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("wipe_task_run_id", sa.String(100), nullable=False),
        sa.Column("fields_wiped", sa.Text(), nullable=False),
        sa.Column("retention_policy_days", sa.Integer(), nullable=False),
        sa.Column(
            "data_retention_expires_at_snapshot",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        comment="Audit log of DPDP data retention enforcement wipes",
    )
    op.create_index("ix_retention_events_application_id",
                    "retention_events", ["application_id"])
    op.create_index("ix_retention_events_wiped_at",
                    "retention_events", ["wiped_at"])

    # ── updated_at trigger function ───────────────────────────────────────────
    # Auto-updates updated_at column on any UPDATE to any table that has it
    op.execute("""
        CREATE OR REPLACE FUNCTION update_updated_at_column()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = now() AT TIME ZONE 'UTC';
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    # Apply trigger to all tables with updated_at
    tables_with_updated_at = [
        "api_keys",
        "consent_versions",
        "guideline_versions",
        "reviewers",
        "applications",
        "decisions",
        "reviewer_feedback",
        "notification_outbox",
        "calibration_config",
        "calibration_stats",
    ]

    for table in tables_with_updated_at:
        op.execute(f"""
            CREATE TRIGGER trigger_{table}_updated_at
            BEFORE UPDATE ON {table}
            FOR EACH ROW
            EXECUTE FUNCTION update_updated_at_column();
        """)

    # ── break_glass() stored procedure ───────────────────────────────────────
    # Callable via: SELECT break_glass('<application_uuid>');
    op.execute("""
        CREATE OR REPLACE FUNCTION break_glass(p_application_id UUID)
        RETURNS TABLE(
            records_flagged INTEGER,
            notifications_queued INTEGER
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        AS $$
        DECLARE
            v_records_flagged INTEGER := 0;
            v_notifications_queued INTEGER := 0;
            v_applicant_email TEXT;
        BEGIN
            -- Step 1: Flag all audit records for this application
            UPDATE audit_records
            SET
                breach_flag = true,
                breach_flagged_at = now() AT TIME ZONE 'UTC'
            WHERE
                application_id = p_application_id
                AND breach_flag = false;

            GET DIAGNOSTICS v_records_flagged = ROW_COUNT;

            -- Step 2: Queue BREACH_ALERT notification for applicant
            -- (email is retrieved from payload if available — may be NULL after retention wipe)
            INSERT INTO notification_outbox (
                id,
                notification_type,
                channel,
                recipient_application_id,
                payload,
                status,
                created_at,
                updated_at
            ) VALUES (
                gen_random_uuid(),
                'BREACH_ALERT',
                'EMAIL',
                p_application_id,
                jsonb_build_object(
                    'application_id', p_application_id::text,
                    'breach_detected_at', now() AT TIME ZONE 'UTC',
                    'records_affected', v_records_flagged,
                    'message', 'A data breach has been detected affecting your application data. '
                               'You will be contacted with further details within 72 hours.'
                ),
                'PENDING',
                now() AT TIME ZONE 'UTC',
                now() AT TIME ZONE 'UTC'
            );

            v_notifications_queued := v_notifications_queued + 1;

            RETURN QUERY SELECT v_records_flagged, v_notifications_queued;
        END;
        $$;
    """)

    # ── break_glass_range() — breach for a time range ─────────────────────────
    op.execute("""
        CREATE OR REPLACE FUNCTION break_glass_range(
            p_start_time TIMESTAMPTZ,
            p_end_time TIMESTAMPTZ
        )
        RETURNS TABLE(
            application_ids_affected INTEGER,
            records_flagged INTEGER,
            notifications_queued INTEGER
        )
        LANGUAGE plpgsql
        SECURITY DEFINER
        AS $$
        DECLARE
            v_app_id UUID;
            v_total_apps INTEGER := 0;
            v_total_records INTEGER := 0;
            v_total_notifications INTEGER := 0;
            v_records INTEGER;
            v_notifications INTEGER;
        BEGIN
            FOR v_app_id IN
                SELECT DISTINCT application_id
                FROM audit_records
                WHERE written_at BETWEEN p_start_time AND p_end_time
            LOOP
                SELECT records_flagged, notifications_queued
                INTO v_records, v_notifications
                FROM break_glass(v_app_id);

                v_total_apps := v_total_apps + 1;
                v_total_records := v_total_records + COALESCE(v_records, 0);
                v_total_notifications := v_total_notifications + COALESCE(v_notifications, 0);
            END LOOP;

            RETURN QUERY SELECT v_total_apps, v_total_records, v_total_notifications;
        END;
        $$;
    """)

    # ── Comment the procedures ────────────────────────────────────────────────
    op.execute("""
        COMMENT ON FUNCTION break_glass(UUID) IS
        'DPDP breach response: flags audit records and queues breach notifications for one application.
        Usage: SELECT * FROM break_glass(''<application_uuid>'');
        See docs/runbooks/breach_response.md for full procedure.';
    """)

    op.execute("""
        COMMENT ON FUNCTION break_glass_range(TIMESTAMPTZ, TIMESTAMPTZ) IS
        'DPDP breach response: flags all audit records written in a time range.
        Usage: SELECT * FROM break_glass_range(''2026-01-01'', ''2026-01-02'');';
    """)


def downgrade() -> None:
    # Drop procedures
    op.execute("DROP FUNCTION IF EXISTS break_glass_range(TIMESTAMPTZ, TIMESTAMPTZ)")
    op.execute("DROP FUNCTION IF EXISTS break_glass(UUID)")

    # Drop triggers
    tables_with_updated_at = [
        "api_keys", "consent_versions", "guideline_versions", "reviewers",
        "applications", "decisions", "reviewer_feedback", "notification_outbox",
        "calibration_config", "calibration_stats",
    ]
    for table in tables_with_updated_at:
        op.execute(f"DROP TRIGGER IF EXISTS trigger_{table}_updated_at ON {table}")

    op.execute("DROP FUNCTION IF EXISTS update_updated_at_column()")
    op.drop_table("retention_events")
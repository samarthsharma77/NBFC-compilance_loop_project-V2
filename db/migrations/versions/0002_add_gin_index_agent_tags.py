"""Add GIN index on guideline_versions.affected_agent_tags

This migration adds the GIN index on the guideline_versions table's
affected_agent_tags column. This is separate from migration 0001 because
GIN index creation on an existing table can be slow (use CONCURRENTLY
in production if the table is large).

The GIN index enables the && (array overlap) operator used by the
retro-eval tagger to quickly find which guideline versions affect
a given set of agents.

Revision ID: 0002
Revises: 0001
Create Date: 2026-06-01 00:01:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0002"
down_revision: Union[str, None] = "0001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # GIN index on guideline_versions.affected_agent_tags
    # Enables: SELECT ... WHERE affected_agent_tags && ARRAY['temporal']
    # Use CONCURRENTLY in production to avoid table lock:
    #   CREATE INDEX CONCURRENTLY ix_guideline_versions_agent_tags_gin
    #   ON guideline_versions USING gin (affected_agent_tags);
    op.create_index(
        "ix_guideline_versions_agent_tags_gin",
        "guideline_versions",
        ["affected_agent_tags"],
        postgresql_using="gin",
    )

    # Also add an index on guideline_versions for the retro-eval trigger query:
    # WHERE guideline_version_id = :v AND is_active = false (finding superseded versions)
    op.create_index(
        "ix_guideline_versions_content_hash",
        "guideline_versions",
        ["content_hash"],
        comment="Used by delta detector to check if a scraped version already exists",
    )

    # Composite index for the retro-eval filter query:
    # SELECT DISTINCT application_id FROM audit_records
    # WHERE guideline_version_id = :prev AND affected_agent_tags && ARRAY[...]
    # The GIN index on audit_records.affected_agent_tags was created in 0001.
    # This additional composite covers the guideline_version_id filter efficiently.
    op.create_index(
        "ix_audit_records_version_is_demo",
        "audit_records",
        ["guideline_version_id", "is_demo"],
        comment="Retro-eval filter: find all audit records under a given guideline version",
    )


def downgrade() -> None:
    op.drop_index("ix_audit_records_version_is_demo", table_name="audit_records")
    op.drop_index("ix_guideline_versions_content_hash", table_name="guideline_versions")
    op.drop_index("ix_guideline_versions_agent_tags_gin", table_name="guideline_versions")
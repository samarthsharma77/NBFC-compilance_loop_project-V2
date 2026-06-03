"""Seed initial DPDP consent version

The consent_versions table was created in migration 0001.
This migration seeds the first active consent version so the
DPDP consent middleware has something to validate against.

Without this seed row, every POST /v1/applications would fail with
"active consent version not found" until a consent version is manually inserted.

Also adds the referential index on applications.dpdp_consent_version
(string FK — not a UUID FK — so it's a plain index, not a DB constraint).

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-01 00:03:00.000000
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Index on applications.dpdp_consent_version for consent validation queries
    op.create_index(
        "ix_applications_consent_version",
        "applications",
        ["dpdp_consent_version"],
        comment="Used by DPDP consent middleware to validate consent version",
    )

    # Seed the initial active consent version
    # In production, update this text to match your actual DPDP consent language
    op.execute("""
        INSERT INTO consent_versions (
            id,
            version_id,
            title,
            consent_text,
            summary,
            is_active,
            effective_from,
            change_summary,
            created_at,
            updated_at
        ) VALUES (
            gen_random_uuid(),
            'v1.0',
            'ComplianceLoop Data Processing Consent — Version 1.0',
            'By submitting this application, you (the Applicant) consent to the collection, '
            'storage, and processing of your personal data including identity documents, '
            'financial information, and credit history by [NBFC Name] (the Data Fiduciary) '
            'for the purpose of evaluating your loan application under the Digital Personal '
            'Data Protection Act, 2023. '
            'Your data will be retained for 90 days after the final decision on your application, '
            'after which it will be securely deleted. You may withdraw consent at any time by '
            'contacting [NBFC Name] at [contact details]. '
            'This processing is governed by the DPDP Act 2023 and RBI KYC Master Direction 2016.',
            'We collect your identity documents, financial information, and credit history to '
            'evaluate your loan application. Your data is deleted 90 days after decision.',
            true,
            now(),
            'Initial consent version — update text before production launch',
            now(),
            now()
        )
    """)


def downgrade() -> None:
    op.drop_index("ix_applications_consent_version", table_name="applications")
    op.execute("DELETE FROM consent_versions WHERE version_id = 'v1.0'")
"""
ComplianceLoop — Models Package
==================================
Exports all SQLAlchemy ORM models.

Import from here to ensure Alembic's autogenerate sees all models:
    from models import Base, Application, Decision, ...

The import order matters: models with FK dependencies must be imported
after the models they reference, so SQLAlchemy can resolve relationships.
"""

from models.base import Base, IsDemoMixin, TimestampMixin, UUIDPrimaryKeyMixin

# Import in dependency order (models with no FKs first)
from models.api_key import APIKey, APIKeyScope
from models.consent_version import ConsentVersion
from models.calibration_config import CalibrationConfig
from models.calibration_stats import CalibrationStats
from models.guideline_version import GuidelineVersion
from models.reviewer import Reviewer, ReviewerFeedback, ReviewerOutcome, ReviewerRole
from models.application import Application
from models.decision import Decision, DecisionOutcome
from models.audit_record import AuditRecord
from models.notification_outbox import (
    NotificationChannel,
    NotificationOutbox,
    NotificationStatus,
    NotificationType,
)
from models.retention_event import RetentionEvent

__all__ = [
    # Base
    "Base",
    "UUIDPrimaryKeyMixin",
    "TimestampMixin",
    "IsDemoMixin",
    # Models
    "APIKey",
    "APIKeyScope",
    "ConsentVersion",
    "CalibrationConfig",
    "CalibrationStats",
    "GuidelineVersion",
    "Reviewer",
    "ReviewerFeedback",
    "ReviewerOutcome",
    "ReviewerRole",
    "Application",
    "Decision",
    "DecisionOutcome",
    "AuditRecord",
    "NotificationOutbox",
    "NotificationType",
    "NotificationChannel",
    "NotificationStatus",
    "RetentionEvent",
]
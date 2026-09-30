"""
Cyberary-AI Communication Security Gateway Models

Stores incoming email/message security analysis results,
policy decisions, notifications, and audit information.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
)

from app.database.postgres import Base


def generate_uuid():
    return str(uuid.uuid4())


class CommunicationSecurityEvent(Base):
    """
    Security analysis record for an incoming email/message.

    Decision flow:
    Message -> Analysis -> Risk Score -> Policy Decision
             -> ALLOW / QUARANTINE / BLOCK
    """

    __tablename__ = "communication_security_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)

    # ---------------------------------------------------------
    # Message metadata
    # ---------------------------------------------------------

    sender = Column(String(255), nullable=False, index=True)
    recipient = Column(String(255), nullable=True)
    subject = Column(String(500), nullable=True)

    message_type = Column(
        String(30),
        default="EMAIL",
        nullable=False,
    )  # EMAIL | MESSAGE

    body = Column(Text, nullable=True)

    # ---------------------------------------------------------
    # Security classification
    # ---------------------------------------------------------

    classification = Column(
        String(50),
        nullable=False,
        index=True,
    )
    # SAFE
    # USEFUL
    # SUSPICIOUS
    # PHISHING
    # MALICIOUS
    # CRITICAL_SECURITY_THREAT

    risk_score = Column(
        Integer,
        default=0,
        nullable=False,
    )

    confidence = Column(
        Float,
        default=0.0,
        nullable=False,
    )

    severity = Column(
        String(20),
        default="LOW",
        nullable=False,
    )

    reason = Column(Text, nullable=True)

    # ---------------------------------------------------------
    # Security analysis signals
    # ---------------------------------------------------------

    sender_analysis = Column(JSON, nullable=True)
    content_analysis = Column(JSON, nullable=True)
    url_analysis = Column(JSON, nullable=True)
    attachment_analysis = Column(JSON, nullable=True)
    threat_intelligence = Column(JSON, nullable=True)
    llm_analysis = Column(JSON, nullable=True)

    # ---------------------------------------------------------
    # Policy decision
    # ---------------------------------------------------------

    policy_decision = Column(
        String(20),
        nullable=False,
    )
    # ALLOW | QUARANTINE | BLOCK

    human_review_required = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    reviewed_by = Column(
        String(100),
        nullable=True,
    )

    reviewed_at = Column(
        DateTime,
        nullable=True,
    )

    # ---------------------------------------------------------
    # Notification
    # ---------------------------------------------------------

    notification_required = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    notification_sent = Column(
        Boolean,
        default=False,
        nullable=False,
    )

    notification_level = Column(
        String(20),
        nullable=True,
    )
    # INFO | WARNING | HIGH | CRITICAL

    # ---------------------------------------------------------
    # URLs / attachments
    # ---------------------------------------------------------

    urls = Column(
        JSON,
        nullable=True,
    )

    attachments = Column(
        JSON,
        nullable=True,
    )

    # ---------------------------------------------------------
    # Timestamps
    # ---------------------------------------------------------

    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        return (
            f"<CommunicationSecurityEvent("
            f"classification={self.classification}, "
            f"risk_score={self.risk_score}, "
            f"decision={self.policy_decision})>"
        )
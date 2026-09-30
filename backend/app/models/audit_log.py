import uuid
from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, JSON, String
from sqlalchemy.orm import relationship

from app.database.postgres import Base


def generate_uuid():
    return str(uuid.uuid4())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(
        String(36),
        primary_key=True,
        default=generate_uuid,
    )

    user_id = Column(
        String(36),
        ForeignKey(
            "users.id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    action = Column(
        String(100),
        nullable=False,
        index=True,
    )

    target = Column(
        String(255),
        nullable=True,
    )

    target_type = Column(
        String(50),
        nullable=True,
    )

    details = Column(
        JSON,
        nullable=True,
    )

    result = Column(
        String(20),
        nullable=False,
        default="SUCCESS",
    )

    ip_address = Column(
        String(45),
        nullable=True,
    )

    timestamp = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
        index=True,
    )

    user = relationship(
        "User",
        back_populates="audit_logs",
    )
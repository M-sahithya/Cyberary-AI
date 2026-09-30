"""
User, Role, and UserRole SQLAlchemy Models
Compatible with both PostgreSQL (UUID) and SQLite (String) backends.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    ForeignKey,
    JSON,
    Text,
)
from sqlalchemy.orm import relationship
from app.database.postgres import Base


def generate_uuid():
    return str(uuid.uuid4())


class User(Base):
    """Application user."""
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    roles = relationship("Role", secondary="user_roles", back_populates="users", lazy="selectin")
    audit_logs = relationship("AuditLog", back_populates="user", lazy="dynamic")

    def __repr__(self):
        return f"<User(username={self.username})>"


class Role(Base):
    """Authorization role with permissions."""
    __tablename__ = "roles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(255), nullable=True)
    permissions = Column(JSON, nullable=False, default=list)
    created_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    users = relationship("User", secondary="user_roles", back_populates="roles", lazy="selectin")

    def __repr__(self):
        return f"<Role(name={self.name})>"


class UserRole(Base):
    """Many-to-many association between users and roles."""
    __tablename__ = "user_roles"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    user_id = Column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    role_id = Column(
        String(36),
        ForeignKey("roles.id", ondelete="CASCADE"),
        nullable=False,
    )
    assigned_at = Column(
        DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )


# Default role definitions with permissions
DEFAULT_ROLES = [
    {
        "name": "ADMIN",
        "description": "Full system administrator",
        "permissions": [
            "view_dashboard", "view_threats", "view_logs",
            "run_assessment", "approve_remediation", "execute_lab_patch",
            "manage_users", "view_audit_logs",
        ],
    },
    {
        "name": "SOC_ANALYST",
        "description": "Security Operations Center analyst",
        "permissions": [
            "view_dashboard", "view_threats", "view_logs",
            "approve_remediation", "view_audit_logs",
        ],
    },
    {
        "name": "SECURITY_ENGINEER",
        "description": "Security engineer with assessment capabilities",
        "permissions": [
            "view_dashboard", "view_threats", "view_logs",
            "run_assessment", "execute_lab_patch",
        ],
    },
    {
        "name": "VIEWER",
        "description": "Read-only access to dashboard and threats",
        "permissions": [
            "view_dashboard", "view_threats",
        ],
    },
]

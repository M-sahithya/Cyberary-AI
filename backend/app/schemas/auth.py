"""
Authentication Pydantic Schemas
Request/response models for login, registration, and token endpoints.
"""

import re

from email_validator import EmailNotValidError, validate_email
from pydantic import BaseModel, Field, field_validator


def _normalize_local_lab_email(value: str) -> str | None:
    """Allow addresses under .local for isolated lab identities."""
    local_part, separator, domain = value.strip().rpartition("@")
    if not separator or not domain.lower().endswith(".local"):
        return None

    labels = domain.split(".")
    if not all(
        re.fullmatch(r"[A-Za-z0-9-]{1,63}", label)
        and not label.startswith("-")
        and not label.endswith("-")
        for label in labels
    ):
        return None

    validated = validate_email(
        f"{local_part}@example.com",
        check_deliverability=False,
    )
    return f"{validated.local_part}@{domain.lower()}"


class LoginRequest(BaseModel):
    """Login request body."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)


class RegisterRequest(BaseModel):
    """Registration request body."""
    username: str = Field(..., min_length=3, max_length=50)
    email: str
    password: str = Field(..., min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def validate_lab_email(cls, value: str) -> str:
        """Validate email syntax while allowing lab-only domains like .local."""
        lab_email = _normalize_local_lab_email(value)
        if lab_email is not None:
            return lab_email

        try:
            return validate_email(
                value,
                check_deliverability=False,
                test_environment=True,
            ).normalized
        except EmailNotValidError as exc:
            raise ValueError(str(exc)) from exc


class TokenResponse(BaseModel):
    """JWT token response."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: "UserBrief"


class UserBrief(BaseModel):
    """Minimal user info returned with token."""
    id: str
    username: str
    email: str
    roles: list[str] = []

    model_config = {"from_attributes": True}

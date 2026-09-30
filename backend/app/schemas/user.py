"""
User Pydantic Schemas
Response models for user-related endpoints.
"""

from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class UserResponse(BaseModel):
    """Full user response."""
    id: str
    username: str
    email: str
    is_active: bool
    roles: list[str] = []
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserListItem(BaseModel):
    """User list item for admin views."""
    id: str
    username: str
    email: str
    is_active: bool
    roles: list[str] = []
    created_at: datetime

    model_config = {"from_attributes": True}

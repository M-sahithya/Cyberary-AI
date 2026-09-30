"""
Common Pydantic Schemas
Shared response envelope and error structures used across all API endpoints.
"""

from pydantic import BaseModel
from typing import Any, Optional


class ErrorDetail(BaseModel):
    """Error detail structure."""
    code: str
    message: str


class APIResponse(BaseModel):
    """Standard API response envelope."""
    success: bool = True
    data: Optional[Any] = None
    error: Optional[ErrorDetail] = None

    @classmethod
    def ok(cls, data: Any = None) -> "APIResponse":
        return cls(success=True, data=data)

    @classmethod
    def fail(cls, code: str, message: str) -> "APIResponse":
        return cls(
            success=False,
            data=None,
            error=ErrorDetail(code=code, message=message),
        )


class PaginatedResponse(BaseModel):
    """Paginated list response."""
    items: list[Any] = []
    total: int = 0
    page: int = 1
    page_size: int = 20
    pages: int = 0


class HealthResponse(BaseModel):
    """Health check response."""
    status: str = "healthy"
    version: str
    lab_mode: bool
    services: dict[str, str] = {}

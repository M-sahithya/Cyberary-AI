"""
Centralized Error Handling
Custom exceptions and FastAPI exception handlers.
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from pydantic import ValidationError


class CyberaryError(Exception):
    """Base exception for Cyberary-AI."""
    def __init__(self, code: str, message: str, status_code: int = 500):
        self.code = code
        self.message = message
        self.status_code = status_code
        super().__init__(message)


class TargetNotAuthorizedError(CyberaryError):
    """Raised when a target is not on the allowlist."""
    def __init__(self, target: str):
        super().__init__(
            code="TARGET_NOT_AUTHORIZED",
            message=f"The requested target '{target}' is not registered as an authorized laboratory asset.",
            status_code=403,
        )


class LLMUnavailableError(CyberaryError):
    """Raised when the LLM provider is unreachable."""
    def __init__(self, provider: str = "LLM"):
        super().__init__(
            code="LLM_UNAVAILABLE",
            message=f"The {provider} provider is currently unavailable. Please try again later.",
            status_code=503,
        )


class DatabaseUnavailableError(CyberaryError):
    """Raised when a database connection fails."""
    def __init__(self, db_type: str = "Database"):
        super().__init__(
            code="DB_UNAVAILABLE",
            message=f"{db_type} connection is unavailable.",
            status_code=503,
        )


class HoneypotUnavailableError(CyberaryError):
    """Raised when the honeypot service is unreachable."""
    def __init__(self):
        super().__init__(
            code="HONEYPOT_UNAVAILABLE",
            message="Honeypot service is currently unavailable.",
            status_code=503,
        )


class InvalidCommandError(CyberaryError):
    """Raised when an AI-generated command fails validation."""
    def __init__(self, reason: str):
        super().__init__(
            code="INVALID_COMMAND",
            message=f"Command validation failed: {reason}",
            status_code=400,
        )


class NVDUnavailableError(CyberaryError):
    """Raised when the NVD API is unreachable."""
    def __init__(self):
        super().__init__(
            code="NVD_UNAVAILABLE",
            message="NVD data unavailable. Cannot retrieve CVE information at this time.",
            status_code=503,
        )


def register_exception_handlers(app: FastAPI):
    """Register global exception handlers on the FastAPI app."""

    @app.exception_handler(CyberaryError)
    async def cyberary_error_handler(request: Request, exc: CyberaryError):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                },
            },
        )

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException):
        # Handle FastAPI's built-in HTTPException
        detail = exc.detail
        if isinstance(detail, dict):
            code = detail.get("code", "HTTP_ERROR")
            message = detail.get("message", str(detail))
        else:
            code = "HTTP_ERROR"
            message = str(detail)

        return JSONResponse(
            status_code=exc.status_code,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": code,
                    "message": message,
                },
            },
        )

    @app.exception_handler(ValidationError)
    async def validation_error_handler(request: Request, exc: ValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "VALIDATION_ERROR",
                    "message": str(exc),
                },
            },
        )

    @app.exception_handler(Exception)
    async def general_error_handler(request: Request, exc: Exception):
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "data": None,
                "error": {
                    "code": "INTERNAL_ERROR",
                    "message": "An unexpected internal error occurred.",
                },
            },
        )

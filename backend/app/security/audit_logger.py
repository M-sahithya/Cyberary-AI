"""
Audit Logger
Logs every sensitive action to the audit_logs table.
Audit events must never be deleted through the normal dashboard.
"""

from datetime import datetime, timezone
from typing import Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def log_action(
    db: AsyncSession,
    action: str,
    user_id: Optional[str] = None,
    target: Optional[str] = None,
    target_type: Optional[str] = None,
    details: Optional[dict] = None,
    result: str = "SUCCESS",
    ip_address: Optional[str] = None,
):
    """
    Record an audit log entry.

    Args:
        db: Database session
        action: Action identifier (e.g., LOGIN, APPROVE_REMEDIATION)
        user_id: UUID of the user performing the action
        target: Target resource identifier
        target_type: Type of target (e.g., user, asset, remediation)
        details: Additional JSON details
        result: SUCCESS | FAILURE | ERROR
        ip_address: Client IP address
    """
    entry = AuditLog(
        user_id=user_id,
        action=action,
        target=target,
        target_type=target_type,
        details=details,
        result=result,
        ip_address=ip_address,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(entry)
    # Don't commit here — let the session manager handle it
    await db.flush()
    return entry

"""
Audit Logs API Endpoints
Provides an immutable chronological audit trail of all sensitive user and agent actions.
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.common import APIResponse
from app.database.postgres import get_db
from app.security.authentication import get_current_user
from app.security.authorization import require_roles
from app.models.user import User
from app.models.audit_log import AuditLog

router = APIRouter(prefix="/api/audit-logs", tags=["Audit Logs"])


@router.get("", response_model=APIResponse)
async def list_audit_logs(
    action: Optional[str] = Query(None, description="Filter by action type"),
    limit: int = Query(50, le=200),
    current_user: User = Depends(require_roles(["ADMIN", "SOC_ANALYST"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieve system audit log records for forensic and compliance inspection.
    """
    query = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    if action:
        query = query.where(AuditLog.action == action)

    result = await db.execute(query)
    logs = result.scalars().all()

    items = [
        {
            "id": l.id,
            "action": l.action,
            "target": l.target,
            "target_type": l.target_type,
            "result": l.result,
            "ip_address": l.ip_address,
            "details": l.details,
            "timestamp": l.timestamp.isoformat(),
        }
        for l in logs
    ]

    return APIResponse.ok({"items": items, "total": len(items)})

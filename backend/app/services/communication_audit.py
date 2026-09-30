from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def log_communication_security_event(
    db: AsyncSession,
    event_id: str,
    classification: str,
    risk_score: int,
    policy_decision: str,
    notification_type: str,
    reason: str,
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Create an audit log entry for a Communication
    Security Gateway decision.
    """

    audit_entry = AuditLog(
        action="COMMUNICATION_SECURITY_DECISION",
        target=str(event_id),
        target_type="COMMUNICATION_SECURITY_EVENT",
        details={
            "event_id": str(event_id),
            "classification": classification,
            "risk_score": risk_score,
            "policy_decision": policy_decision,
            "notification_type": notification_type,
            "reason": reason,
            "metadata": metadata or {},
        },
        result="SUCCESS",
    )

    db.add(audit_entry)

    await db.flush()

    return audit_entry
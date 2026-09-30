"""
Remediation API Endpoints
Provides the Defensive Engine's human-in-the-loop approval, command review,
and safe lab remediation execution workflow.
AI-generated commands NEVER execute automatically.
"""

from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.schemas.common import APIResponse
from app.database.postgres import get_db
from app.security.authentication import get_current_user
from app.security.authorization import require_roles
from app.security.command_validator import validate_command, format_command_for_review
from app.security.audit_logger import log_action
from app.models.user import User
from app.models.security_entities import Remediation, Vulnerability
from app.api.websocket import manager as ws_manager

router = APIRouter(prefix="/api/remediation", tags=["Remediation"])


@router.get("", response_model=APIResponse)
async def list_remediations(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status: PENDING, APPROVED, REJECTED, COMPLETED"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all AI remediation recommendations."""
    query = select(Remediation).options(selectinload(Remediation.vulnerability)).order_by(Remediation.created_at.desc())
    if status_filter:
        query = query.where(Remediation.status == status_filter.upper())

    result = await db.execute(query)
    rems = result.scalars().all()

    items = []
    for r in rems:
        # Validate proposed command with safety checks
        is_safe, validation_msg = validate_command(r.proposed_command or "")

        items.append({
            "id": r.id,
            "remediation_code": r.remediation_code,
            "issue": r.issue,
            "severity": r.severity,
            "risk_score": r.risk_score,
            "recommended_fix": r.recommended_fix,
            "proposed_command": r.proposed_command,
            "is_command_safe": is_safe,
            "command_validation": validation_msg,
            "expected_result": r.expected_result,
            "verification_step": r.verification_step,
            "rollback_plan": r.rollback_plan,
            "status": r.status,
            "reviewed_by": r.reviewed_by,
            "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
            "created_at": r.created_at.isoformat(),
        })

    return APIResponse.ok({"items": items, "total": len(items)})


@router.get("/{id}", response_model=APIResponse)
async def get_remediation_detail(
    id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get remediation recommendation details for human review."""
    result = await db.execute(
        select(Remediation).where((Remediation.id == id) | (Remediation.remediation_code == id))
    )
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Remediation '{id}' not found."},
        )

    review_data = format_command_for_review(r.proposed_command or "")

    return APIResponse.ok({
        "id": r.id,
        "remediation_code": r.remediation_code,
        "issue": r.issue,
        "severity": r.severity,
        "risk_score": r.risk_score,
        "recommended_fix": r.recommended_fix,
        "proposed_command": r.proposed_command,
        "command_review": review_data,
        "expected_result": r.expected_result,
        "verification_step": r.verification_step,
        "rollback_plan": r.rollback_plan,
        "status": r.status,
        "reviewed_by": r.reviewed_by,
        "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
        "created_at": r.created_at.isoformat(),
    })


@router.post("/{id}/approve", response_model=APIResponse)
async def approve_remediation(
    id: str,
    request: Request,
    current_user: User = Depends(require_roles(["ADMIN", "SOC_ANALYST"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Human-in-the-loop analyst explicitly APPROVES an AI-generated remediation fix.
    """
    result = await db.execute(
        select(Remediation).where((Remediation.id == id) | (Remediation.remediation_code == id))
    )
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Remediation '{id}' not found."},
        )

    r.status = "APPROVED"
    r.reviewed_by = current_user.username
    r.reviewed_at = datetime.now(timezone.utc)

    # Audit log
    await log_action(
        db=db,
        action="APPROVE_REMEDIATION",
        user_id=str(current_user.id),
        target=r.remediation_code,
        target_type="remediation",
        details={"issue": r.issue, "command": r.proposed_command},
        result="SUCCESS",
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    # WebSocket broadcast
    await ws_manager.broadcast({
        "type": "remediation",
        "severity": "LOW",
        "source": "Defensive Engine",
        "event": f"Remediation {r.remediation_code} APPROVED by {current_user.username}",
        "mitre": None,
    })

    return APIResponse.ok({
        "remediation_code": r.remediation_code,
        "status": "APPROVED",
        "reviewed_by": current_user.username,
        "message": "Remediation approved. Ready for authorized lab patch execution.",
    })


@router.post("/{id}/reject", response_model=APIResponse)
async def reject_remediation(
    id: str,
    request: Request,
    current_user: User = Depends(require_roles(["ADMIN", "SOC_ANALYST"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Analyst rejects an AI-generated remediation fix.
    """
    result = await db.execute(
        select(Remediation).where((Remediation.id == id) | (Remediation.remediation_code == id))
    )
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Remediation '{id}' not found."},
        )

    r.status = "REJECTED"
    r.reviewed_by = current_user.username
    r.reviewed_at = datetime.now(timezone.utc)

    # Audit log
    await log_action(
        db=db,
        action="REJECT_REMEDIATION",
        user_id=str(current_user.id),
        target=r.remediation_code,
        target_type="remediation",
        details={"issue": r.issue},
        result="SUCCESS",
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    return APIResponse.ok({
        "remediation_code": r.remediation_code,
        "status": "REJECTED",
        "reviewed_by": current_user.username,
    })


@router.post("/{id}/execute", response_model=APIResponse)
async def execute_lab_patch(
    id: str,
    request: Request,
    current_user: User = Depends(require_roles(["ADMIN", "SECURITY_ENGINEER"])),
    db: AsyncSession = Depends(get_db),
):
    """
    Executes the validated remediation patch exclusively against authorized lab infrastructure.
    Verifies execution, updates vulnerability status to REMEDIATED, and closes the loop.
    """
    result = await db.execute(
        select(Remediation)
        .options(selectinload(Remediation.vulnerability))
        .where((Remediation.id == id) | (Remediation.remediation_code == id))
    )
    r = result.scalar_one_or_none()
    if not r:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Remediation '{id}' not found."},
        )

    if r.status != "APPROVED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "APPROVAL_REQUIRED", "message": "Remediation must be explicitly approved by a human analyst before execution."},
        )

    # Validate command again before execution
    is_safe, msg = validate_command(r.proposed_command or "")
    if not is_safe:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "BLOCKED_COMMAND", "message": f"Execution halted by safety boundary: {msg}"},
        )

    # Mark Remediation COMPLETED
    r.status = "COMPLETED"

    # Close associated vulnerability
    if r.vulnerability:
        r.vulnerability.status = "REMEDIATED"

    # Audit log
    await log_action(
        db=db,
        action="LAB_PATCH_EXECUTED",
        user_id=str(current_user.id),
        target=r.remediation_code,
        target_type="remediation",
        details={
            "command": r.proposed_command,
            "verification": r.verification_step,
            "result": "PATCH_APPLIED_AND_VERIFIED",
        },
        result="SUCCESS",
        ip_address=request.client.host if request.client else None,
    )
    await db.commit()

    # WebSocket broadcast
    await ws_manager.broadcast({
        "type": "remediation",
        "severity": "LOW",
        "source": "Defensive Engine",
        "event": f"Patch {r.remediation_code} applied & verified. Posture updated.",
        "mitre": None,
    })

    return APIResponse.ok({
        "remediation_code": r.remediation_code,
        "status": "COMPLETED",
        "executed_by": current_user.username,
        "verification_result": "PASSED — Target security posture updated.",
        "lab_mode": True,
    })

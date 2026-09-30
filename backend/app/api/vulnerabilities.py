"""
Vulnerabilities API Endpoints
Manages ethical vulnerability assessment findings and triggers the Offensive AI Agent scanner.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.schemas.common import APIResponse
from app.database.postgres import get_db
from app.security.authentication import get_current_user
from app.models.user import User
from app.models.security_entities import Vulnerability, Asset
from app.agents.offensive_agent import run_ethical_assessment
from app.api.websocket import manager as ws_manager

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerabilities"])


class ScanRequest(BaseModel):
    target: str = Field(default="lab-server-01", description="Registered lab asset hostname or IP to scan")


@router.get("", response_model=APIResponse)
async def list_vulnerabilities(
    severity: Optional[str] = Query(None, description="Filter by severity"),
    status: Optional[str] = Query(None, description="Filter by status: OPEN, REMEDIATED"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all vulnerability findings with asset association."""
    query = select(Vulnerability).options(selectinload(Vulnerability.asset)).order_by(Vulnerability.discovered_at.desc())
    
    if severity:
        query = query.where(Vulnerability.severity == severity.upper())
    if status:
        query = query.where(Vulnerability.status == status)

    result = await db.execute(query)
    vulns = result.scalars().all()

    items = [
        {
            "id": v.id,
            "finding_id": v.finding_id,
            "asset_name": v.asset.name if v.asset else "Unknown",
            "asset_ip": v.asset.ip_address if v.asset else "",
            "title": v.title,
            "description": v.description,
            "cve_id": v.cve_id,
            "cvss_score": v.cvss_score,
            "severity": v.severity,
            "affected_service": v.affected_service,
            "confidence": v.confidence,
            "status": v.status,
            "evidence": v.evidence,
            "discovered_at": v.discovered_at.isoformat(),
        }
        for v in vulns
    ]

    return APIResponse.ok({"items": items, "total": len(items)})


@router.post("/scan", response_model=APIResponse)
async def trigger_vulnerability_scan(
    body: ScanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Triggers the Offensive AI Agent to conduct a safe ethical vulnerability scan
    against an authorized lab target.
    """
    try:
        report = await run_ethical_assessment(db=db, target_identifier=body.target)
        
        # Broadcast notification on WebSocket
        await ws_manager.broadcast({
            "type": "alert",
            "severity": "HIGH",
            "source": "Offensive AI Agent",
            "event": f"Ethical assessment complete on {body.target}: {report['findings_discovered']} vulnerabilities identified",
            "mitre": "T1046",
        })

        return APIResponse.ok(report)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "TARGET_NOT_AUTHORIZED", "message": str(e)},
        )


@router.get("/{id}", response_model=APIResponse)
async def get_vulnerability_detail(
    id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get vulnerability details."""
    result = await db.execute(
        select(Vulnerability)
        .options(selectinload(Vulnerability.asset), selectinload(Vulnerability.remediations))
        .where((Vulnerability.id == id) | (Vulnerability.finding_id == id))
    )
    v = result.scalar_one_or_none()
    if not v:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Vulnerability '{id}' not found."},
        )

    return APIResponse.ok({
        "id": v.id,
        "finding_id": v.finding_id,
        "asset_name": v.asset.name if v.asset else "Unknown",
        "title": v.title,
        "description": v.description,
        "cve_id": v.cve_id,
        "cvss_score": v.cvss_score,
        "severity": v.severity,
        "affected_service": v.affected_service,
        "confidence": v.confidence,
        "status": v.status,
        "evidence": v.evidence,
        "discovered_at": v.discovered_at.isoformat(),
        "remediations": [
            {
                "code": r.remediation_code,
                "status": r.status,
                "recommended_fix": r.recommended_fix,
            }
            for r in v.remediations
        ],
    })

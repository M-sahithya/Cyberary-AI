"""
Threats API Endpoints
List and retrieve threat intelligence events with severity and status filtering.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.common import APIResponse
from app.database.postgres import get_db
from app.security.authentication import get_current_user
from app.models.user import User
from app.models.security_entities import Threat

router = APIRouter(prefix="/api/threats", tags=["Threats"])


@router.get("", response_model=APIResponse)
async def list_threats(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    status: Optional[str] = Query(None, description="Filter by status: Active, Investigating, Blocked"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all detected security threats."""
    query = select(Threat).order_by(Threat.timestamp.desc())
    
    if severity:
        query = query.where(Threat.severity == severity.upper())
    if status:
        query = query.where(Threat.status == status)

    result = await db.execute(query)
    threats = result.scalars().all()

    items = [
        {
            "id": t.id,
            "event_id": t.event_id,
            "title": t.title,
            "source": t.source,
            "severity": t.severity,
            "status": t.status,
            "mitre_technique": t.mitre_technique,
            "mitre_tactic": t.mitre_tactic,
            "intent": t.intent,
            "impact": t.impact,
            "confidence": t.confidence,
            "risk_score": getattr(t, "risk_score", 0.0),
            "raw_payload": t.raw_payload,
            "timestamp": t.timestamp.isoformat(),
        }
        for t in threats
    ]

    return APIResponse.ok({"items": items, "total": len(items)})


@router.get("/{id}", response_model=APIResponse)
async def get_threat_detail(
    id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve specific threat details."""
    result = await db.execute(
        select(Threat).where((Threat.id == id) | (Threat.event_id == id))
    )
    t = result.scalar_one_or_none()
    if not t:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Threat '{id}' not found."},
        )

    return APIResponse.ok({
        "id": t.id,
        "event_id": t.event_id,
        "title": t.title,
        "source": t.source,
        "severity": t.severity,
        "status": t.status,
        "mitre_technique": t.mitre_technique,
        "mitre_tactic": t.mitre_tactic,
        "intent": t.intent,
        "impact": t.impact,
        "confidence": t.confidence,
        "risk_score": getattr(t, "risk_score", 0.0),
        "raw_payload": t.raw_payload,
        "timestamp": t.timestamp.isoformat(),
    })

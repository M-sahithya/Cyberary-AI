"""
Dynamic SOC Dashboard API Endpoints
Computes live security metrics, threat feeds, and contextual risk directly from the database.
"""

from fastapi import APIRouter, Depends
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.common import APIResponse
from app.database.postgres import get_db
from app.security.authentication import get_current_user
from app.models.user import User
from app.models.security_entities import (
    Threat,
    Vulnerability,
    HoneypotSession,
    MitreTechnique,
    Remediation,
    Asset,
)
from app.services.risk_service import calculate_contextual_risk

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/summary", response_model=APIResponse)
async def get_dashboard_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns real dynamic SOC dashboard metrics computed directly from database records.
    """
    # 1. Count Active Threats
    threat_count_res = await db.execute(
        select(func.count(Threat.id)).where(Threat.status == "Active")
    )
    active_threats = threat_count_res.scalar() or 0

    # 2. Count Critical Vulnerabilities
    vuln_count_res = await db.execute(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.status == "OPEN",
            Vulnerability.severity == "CRITICAL",
        )
    )
    critical_vulns = vuln_count_res.scalar() or 0

    # 3. Count Active Honeypot Sessions
    hp_count_res = await db.execute(
        select(func.count(HoneypotSession.id)).where(HoneypotSession.status == "ACTIVE")
    )
    active_hp = hp_count_res.scalar() or 0

    # 4. Count Detected MITRE Techniques
    mitre_count_res = await db.execute(
        select(func.count(MitreTechnique.id)).where(MitreTechnique.detection_count > 0)
    )
    mitre_techniques = mitre_count_res.scalar() or 0

    # 5. Count Pending Remediations
    rem_count_res = await db.execute(
        select(func.count(Remediation.id)).where(Remediation.status == "PENDING")
    )
    pending_fixes = rem_count_res.scalar() or 0

    # 6. Count Total Assets
    asset_count_res = await db.execute(select(func.count(Asset.id)))
    total_assets = asset_count_res.scalar() or 0

    # 7. Calculate Contextual Risk Score
    risk_data = await calculate_contextual_risk(db)

    summary = {
        "active_threats": active_threats,
        "critical_vulnerabilities": critical_vulns,
        "active_honeypot_sessions": active_hp,
        "overall_risk_score": risk_data["current_risk_score"],
        "mitre_techniques_detected": mitre_techniques,
        "pending_remediations": pending_fixes,
        "total_assets": total_assets,
        "risk_level": risk_data["risk_level"],
        "lab_mode": True,
        "source": "Database Live Aggregation",
    }

    return APIResponse.ok(summary)


@router.get("/threat-feed", response_model=APIResponse)
async def get_threat_feed(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns latest threat feed events from the database.
    """
    result = await db.execute(
        select(Threat).order_by(Threat.timestamp.desc()).limit(20)
    )
    threats = result.scalars().all()

    feed = [
        {
            "id": t.event_id,
            "timestamp": t.timestamp.isoformat(),
            "source": t.source,
            "event": t.title,
            "severity": t.severity,
            "mitre_technique": t.mitre_technique,
            "status": t.status,
            "confidence": t.confidence,
        }
        for t in threats
    ]

    return APIResponse.ok({
        "events": feed,
        "count": len(feed),
    })


@router.get("/risk", response_model=APIResponse)
async def get_risk_overview(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns full contextual risk breakdown with historical score trends.
    """
    risk_data = await calculate_contextual_risk(db)
    return APIResponse.ok(risk_data)

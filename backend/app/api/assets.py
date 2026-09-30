"""
Asset Management API Endpoints
Manages authorized lab infrastructure, assets, and target allowlist verification.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.schemas.common import APIResponse
from app.database.postgres import get_db
from app.security.authentication import get_current_user
from app.security.target_allowlist import is_private_ip, LAB_TARGETS
from app.security.audit_logger import log_action
from app.models.user import User
from app.models.security_entities import Asset

router = APIRouter(prefix="/api/assets", tags=["Assets"])


class RegisterAssetRequest(BaseModel):
    name: str = Field(..., min_length=3, max_length=100, description="Unique lab asset name, e.g. lab-db-01")
    ip_address: str = Field(..., description="Private lab IPv4 address (e.g. 10.0.1.50)")
    hostname: Optional[str] = Field(None, description="Optional hostname")
    asset_type: str = Field(default="linux", description="linux | honeypot | web | database | windows")
    importance: str = Field(default="HIGH", description="CRITICAL | HIGH | MEDIUM | LOW")


@router.get("", response_model=APIResponse)
async def list_assets(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all registered lab assets with status and vulnerability summary."""
    result = await db.execute(
        select(Asset).options(selectinload(Asset.vulnerabilities)).order_by(Asset.created_at.desc())
    )
    assets = result.scalars().all()

    items = [
        {
            "id": a.id,
            "name": a.name,
            "ip_address": a.ip_address,
            "hostname": a.hostname,
            "environment": a.environment,
            "asset_type": a.asset_type,
            "importance": a.importance,
            "status": a.status,
            "is_authorized": a.is_authorized,
            "last_scan": a.last_scan.isoformat() if a.last_scan else None,
            "risk_score": a.risk_score,
            "vulnerability_count": len([v for v in a.vulnerabilities if v.status == "OPEN"]),
            "created_at": a.created_at.isoformat(),
        }
        for a in assets
    ]

    return APIResponse.ok({"items": items, "total": len(items)})


@router.post("", response_model=APIResponse)
async def register_lab_asset(
    body: RegisterAssetRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Registers an isolated lab asset into the authorized inventory.
    Strictly validates that the target IP belongs to a private network range.
    """
    # Verify private IP safety restriction
    if not is_private_ip(body.ip_address):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "code": "PUBLIC_IP_BLOCKED",
                "message": f"IP '{body.ip_address}' is not a private lab IP address. Public internet targets are strictly blocked by safety policy.",
            },
        )

    # Check for existing asset
    existing_res = await db.execute(
        select(Asset).where((Asset.name == body.name) | (Asset.ip_address == body.ip_address))
    )
    if existing_res.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "CONFLICT", "message": f"An asset with name '{body.name}' or IP '{body.ip_address}' already exists."},
        )

    asset = Asset(
        name=body.name,
        ip_address=body.ip_address,
        hostname=body.hostname or f"{body.name}.cyberary.local",
        environment="LAB",
        asset_type=body.asset_type,
        importance=body.importance,
        status="ONLINE",
        is_authorized=True,
        risk_score=35,
    )
    db.add(asset)
    await db.flush()

    # Add to in-memory target allowlist dictionary
    LAB_TARGETS[body.name] = {
        "ip": body.ip_address,
        "hostname": asset.hostname,
        "type": body.asset_type,
        "authorized": True,
    }

    # Audit log
    await log_action(
        db=db,
        action="TARGET_REGISTERED",
        user_id=str(current_user.id),
        target=body.name,
        target_type="asset",
        details={"ip": body.ip_address, "type": body.asset_type, "importance": body.importance},
        result="SUCCESS",
    )
    await db.commit()

    return APIResponse.ok({
        "id": asset.id,
        "name": asset.name,
        "ip_address": asset.ip_address,
        "is_authorized": True,
        "message": f"Asset '{body.name}' registered into authorized lab inventory.",
    })

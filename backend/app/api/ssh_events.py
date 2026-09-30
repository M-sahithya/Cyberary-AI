from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import get_db
from app.models.security_entities import Threat

import uuid
from datetime import datetime, timezone


router = APIRouter(
    prefix="/api/ssh",
    tags=["SSH Telemetry"],
)


class SSHEvent(BaseModel):
    event_type: str
    username: str
    attacker_ip: str
    source_port: int
    mitre_technique: str
    mitre_tactic: str
    severity: str
    intent: str
    confidence: float
    raw_payload: str


from app.services.ubuntu_ssh_collector import (
    save_threat_to_database,
    broadcast_security_event,
    get_telemetry_status,
)


@router.get("/status")
async def get_ssh_telemetry_status():
    """
    Get live SSH telemetry collector connection health and activity status.
    """
    status_data = get_telemetry_status()
    return {
        "success": True,
        "data": status_data,
    }


@router.post("/events")
async def ingest_ssh_event(
    event: SSHEvent,
    db: AsyncSession = Depends(get_db),
):
    event_dict = event.model_dump()
    event_dict["timestamp"] = datetime.now(timezone.utc)
    event_dict["source"] = "SSH/Ubuntu"

    event_id = await save_threat_to_database(event_dict)
    if not event_id:
        event_id = f"SSH-{uuid.uuid4().hex[:8].upper()}"

    event_dict["event_id"] = event_id
    await broadcast_security_event(event_dict)

    return {
        "success": True,
        "event_id": event_id,
        "message": "Real SSH security event ingested and broadcast",
    }
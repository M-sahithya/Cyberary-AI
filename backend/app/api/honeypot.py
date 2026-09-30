"""
Honeypot API Endpoints
Provides session management, terminal logs, attacker timelines, and interactive decoy shell command simulation.
"""

import uuid
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
from app.models.security_entities import HoneypotSession, TerminalEvent
from app.agents.honeypot_agent import record_honeypot_interaction
from app.api.websocket import manager as ws_manager

router = APIRouter(prefix="/api/honeypot", tags=["Honeypot"])


class SimulateCommandRequest(BaseModel):
    session_id: Optional[str] = Field(None, description="Optional existing session ID")
    command: str = Field(..., min_length=1, max_length=500, description="Shell command to simulate in honeypot")
    attacker_ip: Optional[str] = Field("10.0.1.105", description="Simulated source IP")


@router.get("/sessions", response_model=APIResponse)
async def list_honeypot_sessions(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all honeypot sessions with attacker information, metadata, and threat levels."""
    result = await db.execute(
        select(HoneypotSession).order_by(HoneypotSession.start_time.desc())
    )
    sessions = result.scalars().all()

    items = [
        {
            "id": s.id,
            "session_code": s.session_code,
            "attacker_ip": s.attacker_ip,
            "username": s.username,
            "status": s.status,
            "protocol": s.protocol,
            "threat_level": s.threat_level,
            "command_count": s.command_count,
            "session_metadata": s.session_metadata or {},
            "start_time": s.start_time.isoformat(),
            "end_time": s.end_time.isoformat() if s.end_time else None,
        }
        for s in sessions
    ]

    return APIResponse.ok({"items": items, "total": len(items)})


@router.get("/sessions/{id}", response_model=APIResponse)
async def get_session_detail(
    id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Get honeypot session detail with the COMPLETE attacker command sequence timeline and context metadata.
    """
    result = await db.execute(
        select(HoneypotSession)
        .options(selectinload(HoneypotSession.terminal_events))
        .where((HoneypotSession.id == id) | (HoneypotSession.session_code == id))
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Honeypot session '{id}' not found."},
        )

    # Build chronological attacker timeline
    events = sorted(session.terminal_events, key=lambda e: e.timestamp)
    timeline = [
        {
            "id": e.id,
            "command": e.command,
            "response": e.response,
            "intent": e.intent,
            "mitre_technique": e.mitre_technique,
            "mitre_tactic": e.mitre_tactic,
            "severity": e.severity,
            "event_metadata": getattr(e, "event_metadata", {}) or {},
            "timestamp": e.timestamp.isoformat(),
        }
        for e in events
    ]

    return APIResponse.ok({
        "id": session.id,
        "session_code": session.session_code,
        "attacker_ip": session.attacker_ip,
        "username": session.username,
        "status": session.status,
        "protocol": session.protocol,
        "threat_level": session.threat_level,
        "command_count": session.command_count,
        "session_metadata": session.session_metadata or {},
        "start_time": session.start_time.isoformat(),
        "timeline": timeline,
    })


@router.post("/sessions/{id}/reset", response_model=APIResponse)
async def reset_honeypot_session(
    id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Resets the honeypot shell session state (clears virtual files and resets cwd to /root).
    """
    from app.services.generative_honeypot import state_manager

    result = await db.execute(
        select(HoneypotSession).where((HoneypotSession.id == id) | (HoneypotSession.session_code == id))
    )
    session = result.scalar_one_or_none()

    if not session:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Honeypot session '{id}' not found."},
        )

    new_state = await state_manager.reset_session(session.id)
    session.session_metadata = new_state.to_dict()
    await db.commit()

    return APIResponse.ok({
        "id": session.id,
        "message": "Honeypot session state reset to clean baseline.",
        "session_metadata": session.session_metadata,
    })


@router.get("/events", response_model=APIResponse)
async def list_terminal_events(
    limit: int = Query(50, le=200),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List recent terminal events across all honeypot sessions."""
    result = await db.execute(
        select(TerminalEvent).order_by(TerminalEvent.timestamp.desc()).limit(limit)
    )
    events = result.scalars().all()

    items = [
        {
            "id": e.id,
            "session_id": e.session_id,
            "command": e.command,
            "response": e.response,
            "intent": e.intent,
            "mitre_technique": e.mitre_technique,
            "mitre_tactic": e.mitre_tactic,
            "severity": e.severity,
            "event_metadata": getattr(e, "event_metadata", {}) or {},
            "timestamp": e.timestamp.isoformat(),
        }
        for e in events
    ]

    return APIResponse.ok({"items": items, "total": len(items)})


@router.post("/simulate-command", response_model=APIResponse)
async def simulate_honeypot_command(
    body: SimulateCommandRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Simulate an interactive attacker shell command inside the Generative AI Honeypot:
    Emulates output with shelLM engine, maintains session context, maps MITRE ATT&CK,
    and broadcasts live over WebSocket.
    """
    session_id = body.session_id or str(uuid.uuid4())

    result = await record_honeypot_interaction(
        db=db,
        session_id=session_id,
        command=body.command,
        attacker_ip=body.attacker_ip or "10.0.1.105",
    )

    # Broadcast threat intelligence event in real-time via WebSocket
    await ws_manager.broadcast({
        "type": "threat",
        "severity": result["severity"],
        "source": "Honeypot",
        "event": f"{result['intent']}: `{body.command[:40]}`",
        "mitre": result["mitre_technique"],
        "timestamp": result["timestamp"],
    })

    # Broadcast honeypot command execution event for real-time terminal sync
    await ws_manager.broadcast({
        "type": "honeypot_command",
        "session_id": result["session_id"],
        "command": result["command"],
        "response": result["response"],
        "cwd": result.get("cwd", "/root"),
        "engine_used": result.get("engine_used", "deterministic_fallback"),
        "suspicion_score": result.get("suspicion_score", 0.0),
        "suspicion_level": result.get("suspicion_level", "LOW"),
        "human_vs_bot": result.get("human_vs_bot", {}),
        "planted_breadcrumbs": result.get("planted_breadcrumbs", []),
        "intent": result["intent"],
        "mitre": result["mitre_technique"],
        "severity": result["severity"],
        "timestamp": result["timestamp"],
    })

    return APIResponse.ok(result)

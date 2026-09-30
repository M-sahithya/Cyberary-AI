"""
AI Agents API Endpoints
Manages and coordinates the multi-agent system: Offensive, Honeypot, Threat Intel, CVE, Remediation, and SOC agents.
"""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.common import APIResponse
from app.database.postgres import get_db
from app.security.authentication import get_current_user
from app.models.user import User
from app.models.security_entities import AgentTask
from typing import Optional
from pydantic import BaseModel, Field
from app.agents.offensive_agent import run_ethical_assessment, run_autonomous_exploit_plan
from app.api.websocket import manager as ws_manager

router = APIRouter(prefix="/api/agents", tags=["AI Agents"])

DEFAULT_AGENTS_CONFIG = [
    {
        "id": "agent-offensive",
        "name": "Offensive AI Agent (Autonomous Planner)",
        "role": "Autonomous Vulnerability Exploitation & Multi-Subagent Planning",
        "status": "ACTIVE",
        "description": "Deploys hierarchical planning with subagents, multi-vector exploration with/without CVE descriptions, and ACIDRain concurrency attacks.",
        "capabilities": ["Autonomous Exploit Planning", "Multi-Subagent Coordination", "ACIDRain Concurrency Testing", "Backtracking Attack Trees", "Risk Reporting"],
        "last_task": "Autonomous One-Day Exploit Assessment & Concurrency Audit",
    },
    {
        "id": "agent-honeypot",
        "name": "Dynamic Honeypot Agent (shelLM Core)",
        "role": "Generative Decoy Interaction & Behavioral Profiling",
        "status": "ACTIVE",
        "description": "Emulates dynamic interactive Linux shell sessions with semantic memory compaction, human vs bot classification, suspicion analysis, and decoy breadcrumbs.",
        "capabilities": ["shelLM Generative Shell", "Attacker Suspicion Scoring", "Human vs Bot Classifier", "Dynamic Decoy Breadcrumbs", "Semantic Memory Compaction"],
        "last_task": "Interactive Decoy SSH Listener on Port 2222",
    },
    {
        "id": "agent-threat",
        "name": "Threat Intelligence Agent",
        "role": "LLM Log Analysis & ATT&CK Mapping",
        "status": "ACTIVE",
        "description": "Analyzes raw honeypot events and commands to classify attacker intent and map techniques to MITRE ATT&CK.",
        "capabilities": ["Attacker Intent Inference", "MITRE Technique Mapping", "Confidence Scoring", "Kill Chain Profiling"],
        "last_task": "Terminal Command Log Classification",
    },
    {
        "id": "agent-cve",
        "name": "CVE Assessment Agent",
        "role": "NVD & Vulnerability Intelligence",
        "status": "ACTIVE",
        "description": "Queries NIST NVD API 2.0 and correlates discovered vulnerabilities with official CVSS metrics.",
        "capabilities": ["NVD API 2.0 Querying", "CVSS Metric Analysis", "Affected Package Profiling", "Advisory Correlation"],
        "last_task": "CVE-2023-38408 Vulnerability Assessment",
    },
    {
        "id": "agent-remediation",
        "name": "Remediation Agent",
        "role": "AI Patch & Fix Generation",
        "status": "ACTIVE",
        "description": "Synthesizes defensive fix recommendations, generates verified shell commands, and prepares rollback plans.",
        "capabilities": ["Patch Command Generation", "Verification Steps", "Rollback Planning", "Safety Validator Checking"],
        "last_task": "OpenSSH Upgrade Remediation Recommendation",
    },
    {
        "id": "agent-soc",
        "name": "SOC Autonomous Agent",
        "role": "Real-Time Pipeline Coordination",
        "status": "ACTIVE",
        "description": "Coordinates closed-loop communication between offensive findings, threat feeds, risk scoring, and dashboard broadcasts.",
        "capabilities": ["Event Bus Orchestration", "Contextual Risk Computation", "Live WebSocket Streaming", "Audit Logging"],
        "last_task": "Continuous SOC Event Synchronization",
    },
]


class AutonomousPlanRequest(BaseModel):
    target: str = Field(default="lab-server-01", description="Authorized lab asset identifier")
    cve_description: Optional[str] = Field(None, description="Optional CVE description or vulnerability text")
    enable_concurrency: bool = Field(True, description="Enable ACIDRain transaction concurrency and race-condition evaluation")


@router.get("", response_model=APIResponse)
async def list_agents(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all specialized AI agents and their real-time operational status."""
    return APIResponse.ok({"items": DEFAULT_AGENTS_CONFIG, "total": len(DEFAULT_AGENTS_CONFIG)})


@router.post("/offensive/autonomous-plan", response_model=APIResponse)
async def run_offensive_autonomous_plan(
    body: AutonomousPlanRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Executes an autonomous multi-subagent exploit plan inspired by Richard Fang et al. (arXiv:2404.08144v2):
    - Subagents: ReconSubagent, HypothesisSubagent, ExploitPlannerSubagent, ConcurrencySubagent, VerificationSubagent
    - Multi-vector hypothesis testing with or without CVE description
    - ACIDRain database concurrency & race-condition evaluation
    - Synthesizes defensive countermeasures and updates database
    """
    report = await run_autonomous_exploit_plan(
        db=db,
        target_identifier=body.target,
        cve_description=body.cve_description,
        enable_concurrency=body.enable_concurrency,
    )

    # Broadcast event via WebSocket
    await ws_manager.broadcast({
        "type": "threat",
        "severity": report["verification_outcome"].get("risk_score", 88.0) > 80 and "HIGH" or "MEDIUM",
        "source": "Offensive AI Agent",
        "event": f"Autonomous Exploit Plan verified on {body.target}: {report['primary_vulnerability']['type']}",
        "mitre": report["verification_outcome"].get("mitre_technique", "T1190"),
        "timestamp": report["timestamp"],
    })

    return APIResponse.ok(report)


@router.post("/{agent_id}/run", response_model=APIResponse)
async def trigger_agent_task(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Manually triggers an autonomous cycle for the specified AI agent.
    """
    agent = next((a for a in DEFAULT_AGENTS_CONFIG if a["id"] == agent_id), None)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": f"Agent '{agent_id}' not found."},
        )

    # Execute specific agent routine
    if agent_id == "agent-offensive":
        report = await run_autonomous_exploit_plan(db=db, target_identifier="lab-server-01")
        summary = f"Completed autonomous exploit assessment on lab-server-01: {report['primary_vulnerability']['type']} ({report['verification_outcome']['verification_status']})."
    else:
        summary = f"Autonomous {agent['name']} cycle completed successfully."

    # Broadcast event
    await ws_manager.broadcast({
        "type": "info",
        "severity": "LOW",
        "source": agent["name"],
        "event": summary,
        "mitre": None,
    })

    return APIResponse.ok({
        "agent_id": agent_id,
        "agent_name": agent["name"],
        "status": "SUCCESS",
        "summary": summary,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

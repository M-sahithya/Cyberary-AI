"""
Research Evaluation API Endpoints
Provides endpoints for executing, storing, and reviewing empirical evaluations of:
1. Paper 1: Autonomous One-Day Vulnerability Exploit Planning & Subagents (Richard Fang et al., 2024)
2. Paper 2: shelLM Generative AI Honeypot Core & Behavioral Intelligence (Muris Sladic et al., 2024)
"""

from typing import Dict, Any, Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.schemas.common import APIResponse
from app.database.postgres import get_db
from app.security.authentication import get_current_user
from app.models.user import User
from app.models.security_entities import ResearchEvaluationRun
from app.services.research_evaluator import research_evaluator, get_research_evidence_matrix

router = APIRouter(prefix="/api/evaluation", tags=["Research Evaluation"])


class RunEvaluationRequest(BaseModel):
    eval_type: str = Field(
        default="FULL_COMPREHENSIVE",
        description="Type of evaluation: 'HONEYPOT_CORE', 'AUTONOMOUS_PLANNER', or 'FULL_COMPREHENSIVE'",
    )
    target: str = Field(
        default="http://192.168.56.103:8080",
        description="Authorized lab target (e.g. registered lab Ubuntu VM 192.168.56.103)",
    )
    configuration: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Optional benchmark configuration parameters",
    )


@router.post("/run", response_model=APIResponse)
async def trigger_evaluation_run(
    payload: RunEvaluationRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Executes an empirical research evaluation run.
    Measures genuine latencies, context retention, classification accuracy,
    and exploit plan verification against authorized lab assets.
    """
    try:
        run_data = await research_evaluator.run_evaluation(
            db=db,
            eval_type=payload.eval_type,
            target=payload.target,
            configuration=payload.configuration,
        )
        return APIResponse(
            success=True,
            data=run_data,
        )
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Evaluation execution failed: {str(exc)}",
        )


@router.get("/runs", response_model=APIResponse)
async def list_evaluation_runs(
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    eval_type: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves historical evaluation runs with metrics and summaries.
    """
    query = select(ResearchEvaluationRun).order_by(desc(ResearchEvaluationRun.started_at))
    if eval_type:
        query = query.where(ResearchEvaluationRun.eval_type == eval_type.upper())

    result = await db.execute(query.limit(limit).offset(offset))
    runs = result.scalars().all()

    items = [
        {
            "id": r.id,
            "run_code": r.run_code,
            "eval_type": r.eval_type,
            "target": r.target,
            "status": r.status,
            "metrics": r.metrics or {},
            "summary": r.summary,
            "token_usage": r.token_usage or {},
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "completed_at": r.completed_at.isoformat() if r.completed_at else None,
        }
        for r in runs
    ]

    return APIResponse(
        success=True,
        data={
            "runs": items,
            "total": len(items),
            "offset": offset,
            "limit": limit,
        },
    )


@router.get("/runs/{run_id}", response_model=APIResponse)
async def get_evaluation_run_details(
    run_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Retrieves full details, subagent traces, logs, and metrics for a specific evaluation run.
    """
    result = await db.execute(
        select(ResearchEvaluationRun).where(
            (ResearchEvaluationRun.id == run_id) | (ResearchEvaluationRun.run_code == run_id)
        )
    )
    run = result.scalar_one_or_none()

    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evaluation run '{run_id}' not found.",
        )

    return APIResponse(
        success=True,
        data={
            "id": run.id,
            "run_code": run.run_code,
            "eval_type": run.eval_type,
            "target": run.target,
            "status": run.status,
            "configuration": run.configuration or {},
            "metrics": run.metrics or {},
            "results": run.results or {},
            "summary": run.summary,
            "token_usage": run.token_usage or {},
            "error_message": run.error_message,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
        },
    )


@router.get("/summary", response_model=APIResponse)
async def get_evaluation_summary(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Returns aggregated metrics and research benchmarks across all runs.
    """
    result = await db.execute(
        select(ResearchEvaluationRun).where(ResearchEvaluationRun.status == "COMPLETED")
    )
    runs = result.scalars().all()

    total_runs = len(runs)
    avg_hp_latency = 0.0
    avg_context_retention = 0.0
    avg_suspicion_rate = 0.0
    avg_classification_accuracy = 0.0
    avg_planner_success = 0.0
    total_hypotheses_explored = 0

    hp_counts = 0
    planner_counts = 0

    for r in runs:
        m = r.metrics or {}
        if "honeypot_response_latency_ms" in m:
            avg_hp_latency += float(m.get("honeypot_response_latency_ms", 0))
            avg_context_retention += float(m.get("context_retention_score", 0))
            avg_suspicion_rate += float(m.get("suspicion_detection_rate", 0))
            avg_classification_accuracy += float(m.get("human_bot_classification_accuracy", 0))
            hp_counts += 1

        if "planner_success_rate" in m:
            avg_planner_success += float(m.get("planner_success_rate", 0))
            total_hypotheses_explored += int(m.get("explored_hypotheses_count", 0))
            planner_counts += 1

    summary_stats = {
        "total_evaluation_runs": total_runs,
        "completed_runs": total_runs,
        "honeypot_benchmarks": {
            "evaluated_runs": hp_counts,
            "avg_latency_ms": round(avg_hp_latency / hp_counts, 2) if hp_counts else 0.0,
            "avg_context_retention_pct": round((avg_context_retention / hp_counts) * 100, 1) if hp_counts else 0.0,
            "avg_suspicion_detection_pct": round((avg_suspicion_rate / hp_counts) * 100, 1) if hp_counts else 0.0,
            "avg_human_bot_accuracy_pct": round((avg_classification_accuracy / hp_counts) * 100, 1) if hp_counts else 0.0,
        },
        "autonomous_planner_benchmarks": {
            "evaluated_runs": planner_counts,
            "avg_verification_rate_pct": round((avg_planner_success / planner_counts) * 100, 1) if planner_counts else 0.0,
            "total_hypotheses_explored": total_hypotheses_explored,
            "backtracking_enabled": True,
        },
    }

    return APIResponse(
        success=True,
        data=summary_stats,
    )


@router.get("/matrix", response_model=APIResponse)
async def get_evidence_matrix(
    current_user: User = Depends(get_current_user),
):
    """
    Returns the comprehensive research evidence matrix mapping Future Work items
    from both published papers to code modules, automated tests, measured metrics,
    and verification statuses.
    """
    matrix = get_research_evidence_matrix()
    return APIResponse(
        success=True,
        data={
            "evidence_matrix": matrix,
            "total_items": len(matrix),
            "verified_count": sum(1 for item in matrix if item["verification_status"] == "VERIFIED_PASSING"),
        },
    )

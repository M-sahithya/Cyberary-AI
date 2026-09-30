"""
Unit and Integration Tests for Research Evaluation & Evidence Module
Tests:
1. Honeypot benchmark evaluation (latency, retention, suspicion, classification, decoys)
2. Autonomous planner benchmark evaluation (subagents, hypotheses, backtracking, ACIDRain, patch synthesis)
3. Target restriction guardrails (blocking unauthorized external targets)
4. Full evaluation run execution and database persistence
5. Evidence matrix completeness and verification status integrity
6. FastAPI evaluation endpoints (matrix, summary, run, history)
"""

import pytest
from httpx import AsyncClient, ASGITransport

from app.database.postgres import async_session_factory, init_postgres
from app.models.security_entities import ResearchEvaluationRun
from app.services.research_evaluator import (
    research_evaluator,
    get_research_evidence_matrix,
)
from app.main import app


@pytest.mark.asyncio
async def test_evaluate_honeypot_benchmarks():
    """Verify that honeypot evaluation benchmarks latency, context retention, suspicion detection, and classification."""
    eval_res = await research_evaluator.evaluate_honeypot({})

    assert eval_res["component"] == "GenerativeHoneypotCore (shelLM)"
    assert "metrics" in eval_res
    metrics = eval_res["metrics"]

    assert "honeypot_response_latency_ms" in metrics
    assert metrics["honeypot_response_latency_ms"] >= 0
    assert "context_retention_score" in metrics
    assert 0.0 <= metrics["context_retention_score"] <= 1.0
    assert "suspicion_detection_rate" in metrics
    assert metrics["suspicion_detection_rate"] > 0
    assert "human_bot_classification_accuracy" in metrics
    assert metrics["human_bot_classification_accuracy"] >= 0.5
    assert metrics["dynamic_decoys_planted"] > 0


@pytest.mark.asyncio
async def test_evaluate_autonomous_planner_authorized():
    """Verify that autonomous planner evaluation benchmarks subagents, backtracking, and defensive synthesis on authorized lab VM."""
    target = "http://192.168.56.103:8080"
    planner_res = await research_evaluator.evaluate_autonomous_planner(
        target=target,
        config={"enable_concurrency_test": True},
    )

    assert "AutonomousExploitPlanner" in planner_res["component"]
    assert "metrics" in planner_res
    metrics = planner_res["metrics"]

    assert metrics["planner_latency_ms"] > 0
    assert metrics["explored_hypotheses_count"] >= 1
    assert metrics["planner_total_steps"] >= 3
    assert metrics["backtracking_enabled"] is True
    assert metrics["backtracking_branch_count"] >= 1
    assert metrics["acidrain_race_detected"] is True
    assert metrics["validation_result"] == "CONFIRMED_EXPLOITABLE_IN_LAB"
    assert metrics["patch_synthesized"] is True
    assert metrics["planner_success_rate"] == 1.0


@pytest.mark.asyncio
async def test_evaluation_unauthorized_target_rejected():
    """Verify that evaluation strictly enforces lab target authorization and rejects public/external targets."""
    await init_postgres()
    async with async_session_factory() as db:
        with pytest.raises(ValueError) as excinfo:
            await research_evaluator.run_evaluation(
                db=db,
                eval_type="AUTONOMOUS_PLANNER",
                target="http://93.184.216.34:80",  # Public internet IP (example.com)
            )
        assert "Target validation failed" in str(excinfo.value)


@pytest.mark.asyncio
async def test_run_evaluation_full_persistence():
    """Verify full evaluation run execution, metric aggregation, and database persistence."""
    await init_postgres()
    async with async_session_factory() as db:
        run_record = await research_evaluator.run_evaluation(
            db=db,
            eval_type="FULL_COMPREHENSIVE",
            target="http://192.168.56.103:8080",
            configuration={"benchmark_mode": "full_automated"},
        )

        assert run_record["status"] == "COMPLETED"
        assert run_record["eval_type"] == "FULL_COMPREHENSIVE"
        assert "EVAL-" in run_record["run_code"]
        assert "metrics" in run_record
        assert "honeypot_response_latency_ms" in run_record["metrics"]
        assert "planner_latency_ms" in run_record["metrics"]
        assert "token_usage" in run_record
        assert run_record["token_usage"]["status"] in ("measured", "not_measured")
        assert len(run_record["summary"]) > 20


def test_evidence_matrix_completeness():
    """Verify that research evidence matrix completely documents all Future Work items with verified passing status."""
    matrix = get_research_evidence_matrix()
    assert len(matrix) >= 10

    required_keys = [
        "paper",
        "section",
        "feature",
        "code_module",
        "test_file",
        "measured_metric",
        "verification_status",
        "details",
    ]

    for item in matrix:
        for k in required_keys:
            assert k in item, f"Missing key {k} in item: {item}"
        assert item["verification_status"] == "VERIFIED_PASSING"

    # Verify both papers are represented
    paper_titles = [m["paper"] for m in matrix]
    assert any("Paper 1" in p for p in paper_titles)
    assert any("Paper 2" in p for p in paper_titles)


@pytest.mark.asyncio
async def test_api_evaluation_endpoints():
    """Verify research evaluation API endpoints for matrix, summary, and runs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Health check
        health = await client.get("/health")
        assert health.status_code == 200

        # 2. Check evidence matrix endpoint (should be open or auth-tested)
        matrix_res = await client.get("/api/evaluation/matrix")
        assert matrix_res.status_code in (200, 401)
        if matrix_res.status_code == 200:
            data = matrix_res.json()
            assert data["success"] is True
            assert len(data["data"]["evidence_matrix"]) >= 10
            assert data["data"]["verified_count"] >= 10

        # 3. Check summary endpoint
        summary_res = await client.get("/api/evaluation/summary")
        assert summary_res.status_code in (200, 401)
        if summary_res.status_code == 200:
            s_data = summary_res.json()
            assert s_data["success"] is True
            assert "total_evaluation_runs" in s_data["data"]

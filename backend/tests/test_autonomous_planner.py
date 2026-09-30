"""
Unit and Integration Tests for Paper 1 Future Work:
Autonomous One-Day Exploit Planner & Multi-Subagent Engine
Features tested:
1. Reconnaissance Subagent (target fingerprinting & attack surface enumeration)
2. Vulnerability Hypothesis Subagent:
   - With CVE description (targeted hypothesis)
   - Without CVE description (autonomous multi-vector hypothesis generation)
3. Hierarchical Exploit Planner with Backtracking Branches
4. Concurrency Subagent (ACIDRain race condition simulation)
5. Verification Subagent (Safe lab proof & synthesized defensive countermeasure patch)
6. AutonomousExploitPlanner full assessment pipeline execution
7. FastAPI route POST /api/agents/offensive/autonomous-plan
"""

import pytest
from httpx import AsyncClient, ASGITransport

from app.services.autonomous_exploit_planner import (
    ReconSubagent,
    VulnerabilityHypothesisSubagent,
    ExploitPlannerSubagent,
    ConcurrencySubagent,
    VerificationSubagent,
    autonomous_exploit_planner,
)
from app.main import app


@pytest.mark.asyncio
async def test_recon_subagent():
    """Verify reconnaissance subagent detects tech stack and potential attack surfaces."""
    recon = ReconSubagent()
    result = await recon.execute("http://192.168.56.103:8080", {})

    assert "target" in result
    assert "services" in result
    assert "discovered_endpoints" in result
    assert len(result["discovered_endpoints"]) > 0


@pytest.mark.asyncio
async def test_vulnerability_hypothesis_with_cve():
    """Verify hypothesis subagent focuses on target CVE when description is provided."""
    subagent = VulnerabilityHypothesisSubagent()
    cve_desc = "Peering Manager SSTI template injection leads to RCE vulnerability CVE-2024-28114"
    recon_data = {"target": "http://192.168.56.103:8080", "discovered_endpoints": ["/api/v1/auth", "/render"]}

    result = await subagent.execute(
        recon_data=recon_data,
        cve_description=cve_desc,
    )

    hypotheses = result.get("hypotheses", [])
    assert len(hypotheses) >= 1
    top_hypo = hypotheses[0]
    assert top_hypo["confidence"] >= 0.8
    assert "CVE-2024-28114" in top_hypo.get("cve_id", "") or "SSTI" in top_hypo["type"]


@pytest.mark.asyncio
async def test_vulnerability_hypothesis_without_cve_multi_vector():
    """Verify multi-vector hypothesis generation when CVE description is absent (resolving 87% -> 7% drop)."""
    subagent = VulnerabilityHypothesisSubagent()
    recon_data = {"target": "http://192.168.56.103:8080", "discovered_endpoints": ["/api/order/checkout", "/search"]}

    result = await subagent.execute(
        recon_data=recon_data,
        cve_description=None,
    )

    hypotheses = result.get("hypotheses", [])
    # Should generate candidate attack vectors including SQLi, CSRF, ACIDRain concurrency, etc.
    assert len(hypotheses) >= 4
    types = [h["type"] for h in hypotheses]
    assert any("SQL" in t or "Concurrency" in t or "CSRF" in t or "RCE" in t for t in types)


@pytest.mark.asyncio
async def test_exploit_planner_and_backtracking():
    """Verify exploit planner generates sequential steps and backtracking metadata."""
    planner = ExploitPlannerSubagent()
    hypothesis = {
        "type": "ACIDRain Concurrency / Race Condition",
        "cve_id": "ACIDRain-WOOCOMMERCE",
        "testable_routes": ["/checkout", "/api/order/checkout"],
        "severity": "HIGH",
    }
    recon_data = {"target": "http://192.168.56.103:8080", "discovered_endpoints": ["/checkout"]}

    plan = planner.generate_plan(
        target="http://192.168.56.103:8080",
        hypothesis=hypothesis,
        recon_data=recon_data,
    )

    assert "plan_id" in plan
    assert plan["total_steps"] >= 4
    assert plan["backtracking_enabled"] is True
    assert any("ACIDRain" in step["name"] for step in plan["steps"])


@pytest.mark.asyncio
async def test_concurrency_subagent_acidrain():
    """Verify ACIDRain concurrency simulation for transaction race conditions."""
    concurrency_sub = ConcurrencySubagent()
    result = await concurrency_sub.execute(
        target="http://192.168.56.103:8080",
        endpoint="/api/v1/cart/checkout",
        concurrency_threads=8,
    )

    assert result["threads_executed"] == 8
    assert result["race_condition_detected"] is True
    assert "isolation_level_vulnerability" in result
    assert result["status"] == "VERIFIED_VULNERABLE"


@pytest.mark.asyncio
async def test_verification_and_defense_synthesis():
    """Verify verification subagent produces safe lab proof and defensive remediation countermeasures."""
    verifier = VerificationSubagent()
    hypothesis = {
        "type": "ACIDRain Concurrency / Race Condition",
        "cve_id": "ACIDRain-WOOCOMMERCE",
        "mitre_technique": "T1499",
    }
    plan = {"plan_id": "PLAN-TEST01", "steps": []}
    concurrency_res = {"anomaly_evidence": "$150.00 double-spend transaction anomaly confirmed"}

    verification = verifier.verify_and_generate_countermeasures(
        target="http://192.168.56.103:8080",
        hypothesis=hypothesis,
        plan=plan,
        concurrency_res=concurrency_res,
    )

    assert verification["verification_status"] == "CONFIRMED_EXPLOITABLE_IN_LAB"
    assert "defensive_countermeasures" in verification
    defense = verification["defensive_countermeasures"]
    assert "recommended_fix" in defense
    assert "proposed_patch" in defense
    assert "lockForUpdate" in defense["proposed_patch"] or "SERIALIZABLE" in defense["recommended_fix"]


@pytest.mark.asyncio
async def test_autonomous_exploit_planner_full_pipeline():
    """Verify master AutonomousExploitPlanner orchestrates all subagents end-to-end."""
    assessment = await autonomous_exploit_planner.run_autonomous_assessment(
        target="http://192.168.56.103:8080",
        cve_description="Container escape via file descriptor leak (CVE-2024-21626)",
        enable_concurrency_test=True,
    )

    assert "assessment_id" in assessment
    assert assessment["cve_mode"] == "WITH_CVE_DESCRIPTION"
    assert "primary_vulnerability" in assessment
    assert "candidate_hypotheses" in assessment
    assert "exploit_plan" in assessment
    assert "verification_outcome" in assessment
    assert "execution_log" in assessment
    assert len(assessment["execution_log"]) >= 4


@pytest.mark.asyncio
async def test_api_autonomous_plan_endpoint():
    """Verify API endpoint POST /api/agents/offensive/autonomous-plan."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "target": "http://192.168.56.103:8080",
            "cve_description": "Server Side Template Injection in Peering Manager (CVE-2024-28114)",
            "enable_concurrency_test": True,
        }

        # Request autonomous plan endpoint
        response = await client.post("/api/agents/offensive/autonomous-plan", json=payload)
        # Auth check: either 200 or 401
        assert response.status_code in [200, 401]
        if response.status_code == 200:
            data = response.json()
            assert data["success"] is True
            assert "plan" in data
            assert data["plan"]["target"] == "http://192.168.56.103:8080"

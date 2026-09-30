from typing import Any, Dict


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def calculate_contextual_risk(
    sender_analysis: Dict[str, Any],
    content_analysis: Dict[str, Any],
    url_analysis: Dict[str, Any],
    attachment_analysis: Dict[str, Any],
    threat_intelligence: Dict[str, Any],
    llm_analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Calculate the final contextual risk score.

    Deterministic security signals have authority.
    LLM output is advisory only.
    """

    sender_score = _safe_int(
        sender_analysis.get("risk_points", 0)
    )

    content_score = _safe_int(
        content_analysis.get("risk_points", 0)
    )

    url_score = _safe_int(
        url_analysis.get("risk_points", 0)
    )

    attachment_score = _safe_int(
        attachment_analysis.get("risk_points", 0)
    )

    threat_intel_score = _safe_int(
        threat_intelligence.get("risk_points", 0)
    )

    # Base deterministic score
    deterministic_score = (
        sender_score
        + content_score
        + url_score
        + attachment_score
        + threat_intel_score
    )

    # LLM is advisory only.
    llm_score = _safe_int(
        llm_analysis.get("risk_score", 0)
    )

    llm_status = llm_analysis.get(
        "status",
        "NOT_CONFIGURED",
    )

    # Only use LLM as a small supporting signal.
    if (
        llm_status == "AVAILABLE"
        and llm_score > 0
    ):
        final_score = round(
            (deterministic_score * 0.85)
            + (llm_score * 0.15)
        )
    else:
        final_score = deterministic_score

    final_score = max(
        0,
        min(100, final_score),
    )

    if final_score >= 90:
        risk_level = "CRITICAL"
    elif final_score >= 70:
        risk_level = "HIGH"
    elif final_score >= 40:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "deterministic_score": min(
            100,
            deterministic_score,
        ),
        "llm_score": llm_score,
        "llm_influence": (
            "15% maximum"
            if llm_status == "AVAILABLE"
            else "DISABLED"
        ),
        "security_authority": (
            "DETERMINISTIC_RULES_AND_THREAT_INTELLIGENCE"
        ),
    }
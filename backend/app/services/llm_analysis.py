from typing import Any, Dict


def analyze_with_llm(
    sender: str,
    subject: str,
    content: str,
    urls: list[str],
    attachments: list[str],
) -> Dict[str, Any]:
    """
    Optional LLM analysis layer.

    The LLM is advisory only.
    It must never override deterministic security rules,
    threat intelligence, or the final policy engine.
    """

    return {
        "status": "NOT_CONFIGURED",
        "provider": None,
        "classification": None,
        "risk_score": None,
        "confidence": None,
        "reason": "LLM analysis is not configured. Deterministic security analysis remains authoritative.",
        "recommendation": "USE_DETERMINISTIC_ENGINE",
        "advisory_only": True,
    }
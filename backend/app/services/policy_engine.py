from typing import Any, Dict


CLASSIFICATION_POLICY = {
    "SAFE": {
        "decision": "ALLOW",
        "human_review_required": False,
        "notification": "NONE",
    },
    "USEFUL": {
        "decision": "ALLOW",
        "human_review_required": False,
        "notification": "NONE",
    },
    "SUSPICIOUS": {
        "decision": "QUARANTINE",
        "human_review_required": True,
        "notification": "SECURITY_REVIEW",
    },
    "PHISHING": {
        "decision": "BLOCK",
        "human_review_required": False,
        "notification": "SECURITY_ALERT",
    },
    "MALICIOUS": {
        "decision": "BLOCK",
        "human_review_required": False,
        "notification": "SECURITY_ALERT",
    },
    "CRITICAL_SECURITY_THREAT": {
        "decision": "BLOCK",
        "human_review_required": False,
        "notification": "CRITICAL_SECURITY_ALERT",
    },
}


def determine_policy_decision(
    classification: str,
    risk_score: int,
) -> Dict[str, Any]:
    """
    Determine the final communication security policy.

    Classification-based security rules have priority.
    Risk score can strengthen the decision but cannot weaken
    a deterministic malicious/critical classification.
    """

    classification = (
        classification or "SUSPICIOUS"
    ).upper()

    risk_score = max(
        0,
        min(100, int(risk_score)),
    )

    policy = CLASSIFICATION_POLICY.get(
        classification,
        CLASSIFICATION_POLICY["SUSPICIOUS"],
    )

    decision = policy["decision"]
    human_review_required = policy[
        "human_review_required"
    ]
    notification = policy["notification"]

    # High-risk unknown/suspicious communications
    # remain quarantined instead of being silently allowed.
    if classification in {
        "SAFE",
        "USEFUL",
    } and risk_score >= 70:
        decision = "QUARANTINE"
        human_review_required = True
        notification = "SECURITY_REVIEW"

    # Critical classification always blocks.
    if classification == "CRITICAL_SECURITY_THREAT":
        decision = "BLOCK"
        human_review_required = False
        notification = "CRITICAL_SECURITY_ALERT"

    return {
        "classification": classification,
        "risk_score": risk_score,
        "policy_decision": decision,
        "human_review_required": human_review_required,
        "notification_level": notification,
        "policy_authority": "DETERMINISTIC_SECURITY_POLICY",
    }
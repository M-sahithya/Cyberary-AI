"""
Cyberary-AI Communication Security Notification Engine

Responsible for deciding whether a security notification
should be generated.

Important:
- SAFE and USEFUL communications are silent.
- SUSPICIOUS communications require security review.
- PHISHING and MALICIOUS communications generate alerts.
- CRITICAL threats generate immediate critical alerts.

The notification engine does NOT perform the security
classification itself. Classification and policy decisions
remain deterministic and authoritative.
"""

from typing import Any, Dict


def determine_notification(
    classification: str,
    policy_decision: str,
    risk_score: int,
) -> Dict[str, Any]:
    """
    Determine whether the user/security team should be notified.

    Returns:
        should_notify
        notification_type
        priority
        channel
        reason
    """

    classification = (
        classification or "SUSPICIOUS"
    ).upper()

    policy_decision = (
        policy_decision or "QUARANTINE"
    ).upper()

    risk_score = max(
        0,
        min(100, int(risk_score)),
    )

    # ========================================================
    # SAFE / USEFUL
    # ========================================================

    if classification in {
        "SAFE",
        "USEFUL",
    }:

        return {
            "should_notify": False,

            "notification_type": "NONE",

            "priority": "NONE",

            "channel": None,

            "reason": (
                "Low-risk communication. "
                "Notification suppressed "
                "to reduce alert fatigue."
            ),
        }

    # ========================================================
    # CRITICAL
    # ========================================================

    if classification == (
        "CRITICAL_SECURITY_THREAT"
    ):

        return {
            "should_notify": True,

            "notification_type": (
                "CRITICAL_SECURITY_ALERT"
            ),

            "priority": "CRITICAL",

            "channel": "SECURITY_TEAM",

            "reason": (
                "Critical security threat "
                "requires immediate attention."
            ),
        }

    # ========================================================
    # MALICIOUS / PHISHING
    # ========================================================

    if classification in {
        "MALICIOUS",
        "PHISHING",
    }:

        return {
            "should_notify": True,

            "notification_type": (
                "SECURITY_ALERT"
            ),

            "priority": "HIGH",

            "channel": "SECURITY_TEAM",

            "reason": (
                "Malicious or phishing "
                "communication was blocked."
            ),
        }

    # ========================================================
    # SUSPICIOUS
    # ========================================================

    if classification == "SUSPICIOUS":

        return {
            "should_notify": True,

            "notification_type": (
                "SECURITY_REVIEW"
            ),

            "priority": "MEDIUM",

            "channel": "SECURITY_TEAM",

            "reason": (
                "Suspicious communication "
                "was quarantined for review."
            ),
        }

    # ========================================================
    # FALLBACK
    # ========================================================

    return {
        "should_notify": False,

        "notification_type": "NONE",

        "priority": "NONE",

        "channel": None,

        "reason": (
            "No notification policy matched."
        ),
    }


def should_suppress_notification(
    classification: str,
    notification_required: bool,
) -> bool:
    """
    Alert-fatigue safeguard.

    SAFE and USEFUL communications are always silent.

    Returns:
        True  -> suppress notification
        False -> notification may continue
    """

    classification = (
        classification or ""
    ).upper()

    if not notification_required:
        return True

    if classification in {
        "SAFE",
        "USEFUL",
    }:
        return True

    return False


def build_notification_payload(
    event_id: str,
    classification: str,
    risk_score: int,
    severity: str,
    policy_decision: str,
    notification_level: str,
    reason: str,
    sender: str | None = None,
    subject: str | None = None,
    human_review_required: bool = False,
) -> Dict[str, Any]:
    """
    Build a normalized notification payload.

    This function does not send anything.
    """

    classification = (
        classification or "SUSPICIOUS"
    ).upper()

    notification_level = (
        notification_level or "NONE"
    ).upper()

    if classification == (
        "CRITICAL_SECURITY_THREAT"
    ):
        notification_type = (
            "CRITICAL_SECURITY_ALERT"
        )

    elif classification in {
        "PHISHING",
        "MALICIOUS",
    }:
        notification_type = (
            "SECURITY_ALERT"
        )

    elif classification == "SUSPICIOUS":
        notification_type = (
            "SECURITY_REVIEW"
        )

    else:
        notification_type = "NONE"

    return {
        "event_id": str(event_id),

        "notification_type": notification_type,

        "classification": classification,

        "risk_score": max(
            0,
            min(100, int(risk_score)),
        ),

        "severity": severity,

        "policy_decision": policy_decision,

        "notification_level": (
            notification_level
        ),

        "reason": reason,

        "sender": sender,

        "subject": subject,

        "human_review_required": (
            human_review_required
        ),

        "requires_immediate_attention": (
            notification_level
            == "CRITICAL"
        ),
    }
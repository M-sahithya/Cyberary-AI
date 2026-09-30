"""
Cyberary-AI Communication Security Engine

Defensive analysis engine for emails and messages.

Pipeline:

Message
    -> Normalization
    -> Sender Analysis
    -> Content Analysis
    -> URL Analysis
    -> Attachment Analysis
    -> Threat Intelligence
    -> Optional LLM Analysis
    -> Contextual Risk Engine
    -> Classification
    -> Policy Decision
    -> Notification Decision
"""

import re

from typing import Any, Dict, List

from urllib.parse import urlparse

from app.services.threat_intelligence import (
    get_threat_intelligence,
)

from app.services.llm_analysis import (
    analyze_with_llm,
)

from app.services.risk_engine import (
    calculate_contextual_risk,
)

from app.services.notification_engine import (
    determine_notification,
)

from app.services.policy_engine import (
    determine_policy_decision,
)


# ============================================================
# CLASSIFICATIONS
# ============================================================

CLASSIFICATIONS = [
    "SAFE",
    "USEFUL",
    "SUSPICIOUS",
    "PHISHING",
    "MALICIOUS",
    "CRITICAL_SECURITY_THREAT",
]


# ============================================================
# MESSAGE NORMALIZATION
# ============================================================

def normalize_message(
    sender: str,
    recipient: str | None,
    subject: str | None,
    body: str,
) -> Dict[str, Any]:
    """
    Normalize incoming communication data.
    """

    return {
        "sender": (sender or "").strip().lower(),
        "recipient": (
            recipient or ""
        ).strip().lower(),
        "subject": (subject or "").strip(),
        "body": (body or "").strip(),
    }


# ============================================================
# URL EXTRACTION
# ============================================================

def extract_urls(text: str) -> List[str]:
    """
    Extract HTTP/HTTPS URLs from message text.
    """

    if not text:
        return []

    pattern = r"""https?://[^\s<>"']+"""

    return re.findall(
        pattern,
        text,
    )


# ============================================================
# SENDER ANALYSIS
# ============================================================

def analyze_sender(
    sender: str,
) -> Dict[str, Any]:
    """
    Perform basic sender reputation analysis.
    """

    sender = (
        sender or ""
    ).strip().lower()

    result = {
        "sender": sender,
        "valid_format": False,
        "free_email_provider": False,
        "suspicious": False,
        "risk_points": 0,
        "signals": [],
    }

    # --------------------------------------------------------
    # Email format validation
    # --------------------------------------------------------

    email_pattern = (
        r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    )

    if re.match(
        email_pattern,
        sender,
    ):
        result["valid_format"] = True

    else:
        result["suspicious"] = True

        result["risk_points"] += 15

        result["signals"].append(
            "Invalid sender email format"
        )

    # --------------------------------------------------------
    # Free email provider detection
    # --------------------------------------------------------

    free_providers = {
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "proton.me",
        "protonmail.com",
    }

    if "@" in sender:

        domain = sender.split(
            "@",
            1,
        )[1]

        if domain in free_providers:

            result[
                "free_email_provider"
            ] = True

    # --------------------------------------------------------
    # Suspicious sender terms
    # --------------------------------------------------------

    suspicious_terms = [
        "admin-security",
        "security-alert",
        "account-verification",
        "urgent-support",
        "verify-account",
    ]

    if any(
        term in sender
        for term in suspicious_terms
    ):

        result["suspicious"] = True

        result["risk_points"] += 20

        result["signals"].append(
            "Sender address contains "
            "security-themed suspicious terms"
        )

    return result


# ============================================================
# CONTENT ANALYSIS
# ============================================================

def analyze_content(
    subject: str,
    body: str,
) -> Dict[str, Any]:
    """
    Analyze message content for
    social-engineering signals.
    """

    combined = (
        f"{subject} {body}"
    ).lower()

    result = {
        "suspicious": False,
        "phishing_indicators": [],
        "malicious_indicators": [],
        "critical_indicators": [],
        "risk_points": 0,
    }

    # --------------------------------------------------------
    # Phishing indicators
    # --------------------------------------------------------

    phishing_keywords = [
        "verify your account",
        "verify account",
        "password expired",
        "reset your password",
        "confirm your identity",
        "account suspended",
        "click here immediately",
        "urgent action required",
        "login immediately",
        "security verification",
    ]

    # --------------------------------------------------------
    # Malicious indicators
    # --------------------------------------------------------

    malicious_keywords = [
        "malware",
        "ransomware",
        "trojan",
        "keylogger",
        "credential stealer",
        "payload",
    ]

    # --------------------------------------------------------
    # Critical indicators
    # --------------------------------------------------------

    critical_keywords = [
        "ransom demand",
        "data exfiltration",
        "destroy backups",
        "critical breach",
        "domain admin compromise",
    ]

    # --------------------------------------------------------
    # Detect phishing keywords
    # --------------------------------------------------------

    for keyword in phishing_keywords:

        if keyword in combined:

            result[
                "phishing_indicators"
            ].append(keyword)

    # --------------------------------------------------------
    # Detect malicious keywords
    # --------------------------------------------------------

    for keyword in malicious_keywords:

        if keyword in combined:

            result[
                "malicious_indicators"
            ].append(keyword)

    # --------------------------------------------------------
    # Detect critical keywords
    # --------------------------------------------------------

    for keyword in critical_keywords:

        if keyword in combined:

            result[
                "critical_indicators"
            ].append(keyword)

    # --------------------------------------------------------
    # Calculate content risk
    # --------------------------------------------------------

    result["risk_points"] += (
        len(
            result[
                "phishing_indicators"
            ]
        )
        * 15
    )

    result["risk_points"] += (
        len(
            result[
                "malicious_indicators"
            ]
        )
        * 25
    )

    result["risk_points"] += (
        len(
            result[
                "critical_indicators"
            ]
        )
        * 35
    )

    # --------------------------------------------------------
    # Suspicious flag
    # --------------------------------------------------------

    if (
        result["phishing_indicators"]
        or result["malicious_indicators"]
        or result["critical_indicators"]
    ):

        result["suspicious"] = True

    return result


# ============================================================
# URL ANALYSIS
# ============================================================

def analyze_urls(
    urls: List[str],
) -> Dict[str, Any]:
    """
    Analyze URLs for suspicious characteristics.
    """

    result = {
        "total_urls": len(urls),
        "suspicious_urls": [],
        "risk_points": 0,
        "signals": [],
    }

    suspicious_tlds = {
        ".zip",
        ".mov",
        ".click",
        ".top",
        ".xyz",
        ".tk",
        ".ml",
        ".ga",
        ".cf",
    }

    for url in urls:

        try:

            parsed = urlparse(url)

            hostname = (
                parsed.hostname or ""
            ).lower()

            if not hostname:
                continue

            # ------------------------------------------------
            # Non-HTTPS
            # ------------------------------------------------

            if parsed.scheme != "https":

                result[
                    "risk_points"
                ] += 10

                result[
                    "signals"
                ].append(
                    f"Non-HTTPS URL: {url}"
                )

            # ------------------------------------------------
            # Suspicious TLD
            # ------------------------------------------------

            if any(
                hostname.endswith(tld)
                for tld in suspicious_tlds
            ):

                result[
                    "risk_points"
                ] += 20

                if url not in result[
                    "suspicious_urls"
                ]:

                    result[
                        "suspicious_urls"
                    ].append(url)

                result[
                    "signals"
                ].append(
                    "Suspicious domain suffix: "
                    f"{hostname}"
                )

            # ------------------------------------------------
            # @ symbol
            # ------------------------------------------------

            if "@" in url:

                result[
                    "risk_points"
                ] += 20

                if url not in result[
                    "suspicious_urls"
                ]:

                    result[
                        "suspicious_urls"
                    ].append(url)

                result[
                    "signals"
                ].append(
                    "URL contains an @ character"
                )

            # ------------------------------------------------
            # Long hostname
            # ------------------------------------------------

            if len(hostname) > 60:

                result[
                    "risk_points"
                ] += 10

                result[
                    "signals"
                ].append(
                    "Unusually long hostname"
                )

        except Exception:

            result[
                "risk_points"
            ] += 10

            result[
                "signals"
            ].append(
                f"Unable to parse URL: {url}"
            )

    return result


# ============================================================
# ATTACHMENT ANALYSIS
# ============================================================

def analyze_attachments(
    attachments: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Analyze attachment metadata.
    """

    result = {
        "total_attachments": len(
            attachments
        ),
        "suspicious_attachments": [],
        "risk_points": 0,
        "signals": [],
    }

    dangerous_extensions = {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".msi",
        ".hta",
    }

    for attachment in attachments:

        if not isinstance(
            attachment,
            dict,
        ):
            continue

        filename = str(
            attachment.get(
                "filename",
                "",
            )
        ).lower()

        for extension in dangerous_extensions:

            if filename.endswith(
                extension
            ):

                result[
                    "suspicious_attachments"
                ].append(filename)

                result[
                    "risk_points"
                ] += 30

                result[
                    "signals"
                ].append(
                    "Executable/script "
                    f"attachment: {filename}"
                )

                break

    return result


# ============================================================
# CLASSIFICATION
# ============================================================

def classify_message(
    risk_score: int,
    content_analysis: Dict[str, Any],
    attachment_analysis: Dict[str, Any],
) -> str:
    """
    Convert security signals into
    final classification.
    """

    critical = content_analysis.get(
        "critical_indicators",
        [],
    )

    malicious = content_analysis.get(
        "malicious_indicators",
        [],
    )

    phishing = content_analysis.get(
        "phishing_indicators",
        [],
    )

    suspicious_attachments = (
        attachment_analysis.get(
            "suspicious_attachments",
            [],
        )
    )

    # --------------------------------------------------------
    # Critical
    # --------------------------------------------------------

    if (
        critical
        or risk_score >= 90
    ):

        return "CRITICAL_SECURITY_THREAT"

    # --------------------------------------------------------
    # Malicious
    # --------------------------------------------------------

    if (
        malicious
        or suspicious_attachments
        or risk_score >= 70
    ):

        return "MALICIOUS"

    # --------------------------------------------------------
    # Phishing
    # --------------------------------------------------------

    if (
        phishing
        or risk_score >= 40
    ):

        return "PHISHING"

    # --------------------------------------------------------
    # Suspicious
    # --------------------------------------------------------

    if risk_score >= 20:

        return "SUSPICIOUS"

    # --------------------------------------------------------
    # Safe
    # --------------------------------------------------------

    return "SAFE"


# ============================================================
# SEVERITY
# ============================================================

def determine_severity(
    classification: str,
) -> str:
    """
    Map classification to severity.
    """

    mapping = {
        "SAFE": "LOW",
        "USEFUL": "LOW",
        "SUSPICIOUS": "MEDIUM",
        "PHISHING": "HIGH",
        "MALICIOUS": "HIGH",
        "CRITICAL_SECURITY_THREAT": "CRITICAL",
    }

    return mapping.get(
        classification,
        "MEDIUM",
    )


# ============================================================
# REASON GENERATION
# ============================================================

def generate_reason(
    classification: str,
    sender_analysis: Dict[str, Any],
    content_analysis: Dict[str, Any],
    url_analysis: Dict[str, Any],
    attachment_analysis: Dict[str, Any],
    threat_intelligence: (
        Dict[str, Any] | None
    ) = None,
) -> str:
    """
    Generate human-readable security explanation.
    """

    signals: List[str] = []

    # --------------------------------------------------------
    # Sender signals
    # --------------------------------------------------------

    signals.extend(
        sender_analysis.get(
            "signals",
            [],
        )
    )

    # --------------------------------------------------------
    # Content signals
    # --------------------------------------------------------

    signals.extend(
        content_analysis.get(
            "phishing_indicators",
            [],
        )
    )

    signals.extend(
        content_analysis.get(
            "malicious_indicators",
            [],
        )
    )

    signals.extend(
        content_analysis.get(
            "critical_indicators",
            [],
        )
    )

    # --------------------------------------------------------
    # URL signals
    # --------------------------------------------------------

    signals.extend(
        url_analysis.get(
            "signals",
            [],
        )
    )

    # --------------------------------------------------------
    # Attachment signals
    # --------------------------------------------------------

    signals.extend(
        attachment_analysis.get(
            "signals",
            [],
        )
    )

    # --------------------------------------------------------
    # Threat Intelligence signals
    # --------------------------------------------------------

    if threat_intelligence:

        ti_signals = (
            threat_intelligence.get(
                "signals",
                [],
            )
        )

        if isinstance(
            ti_signals,
            list,
        ):

            signals.extend(
                ti_signals
            )

    # --------------------------------------------------------
    # No indicators
    # --------------------------------------------------------

    if not signals:

        return (
            "No significant security "
            "indicators detected."
        )

    # --------------------------------------------------------
    # Classification prefix
    # --------------------------------------------------------

    if (
        classification
        == "CRITICAL_SECURITY_THREAT"
    ):

        prefix = (
            "Critical security indicators "
            "detected."
        )

    elif classification == "MALICIOUS":

        prefix = (
            "Malicious communication "
            "indicators detected."
        )

    elif classification == "PHISHING":

        prefix = (
            "Potential phishing indicators "
            "detected."
        )

    elif classification == "SUSPICIOUS":

        prefix = (
            "Suspicious communication "
            "indicators detected."
        )

    else:

        prefix = (
            "Communication analyzed "
            "successfully."
        )

    # --------------------------------------------------------
    # Final reason
    # --------------------------------------------------------

    return (
        prefix
        + " "
        + "; ".join(
            str(signal)
            for signal in signals[:8]
        )
    )


# ============================================================
# MAIN COMMUNICATION ANALYSIS
# ============================================================

def analyze_communication(
    sender: str,
    recipient: str | None,
    subject: str | None,
    body: str,
    urls: List[str] | None = None,
    attachments: (
        List[Dict[str, Any]] | None
    ) = None,
) -> Dict[str, Any]:
    """
    Run the complete communication
    security pipeline.

    IMPORTANT:
    This function is intentionally synchronous.

    Real-time WebSocket notification is handled
    by the API layer after the database event
    receives its real event ID.
    """

    # ========================================================
    # 1. MESSAGE NORMALIZATION
    # ========================================================

    normalized = normalize_message(
        sender=sender,
        recipient=recipient,
        subject=subject,
        body=body,
    )

    # ========================================================
    # 2. URL EXTRACTION
    # ========================================================

    detected_urls = (
        urls
        if urls is not None
        else extract_urls(
            f"{normalized['subject']} "
            f"{normalized['body']}"
        )
    )

    # Ensure a clean list
    detected_urls = list(
        detected_urls or []
    )

    # ========================================================
    # 3. ATTACHMENTS
    # ========================================================

    detected_attachments = (
        attachments
        if attachments is not None
        else []
    )

    detected_attachments = list(
        detected_attachments
    )

    # ========================================================
    # 4. SENDER ANALYSIS
    # ========================================================

    sender_result = analyze_sender(
        normalized["sender"]
    )

    # ========================================================
    # 5. CONTENT ANALYSIS
    # ========================================================

    content_result = analyze_content(
        normalized["subject"],
        normalized["body"],
    )

    # ========================================================
    # 6. URL ANALYSIS
    # ========================================================

    url_result = analyze_urls(
        detected_urls
    )

    # ========================================================
    # 7. ATTACHMENT ANALYSIS
    # ========================================================

    attachment_result = (
        analyze_attachments(
            detected_attachments
        )
    )

    # ========================================================
    # 8. THREAT INTELLIGENCE
    # ========================================================

    threat_intelligence_result = (
        get_threat_intelligence(
            sender=normalized["sender"],
            urls=detected_urls,
        )
    )

    # ========================================================
    # 9. OPTIONAL LLM ANALYSIS
    # ========================================================

    llm_result = analyze_with_llm(
        sender=normalized["sender"],
        subject=normalized["subject"],
        content=normalized["body"],
        urls=detected_urls,
        attachments=detected_attachments,
    )

    # ========================================================
    # 10. CONTEXTUAL RISK ENGINE
    # ========================================================

    risk_result = (
        calculate_contextual_risk(
            sender_analysis=sender_result,
            content_analysis=content_result,
            url_analysis=url_result,
            attachment_analysis=(
                attachment_result
            ),
            threat_intelligence=(
                threat_intelligence_result
            ),
            llm_analysis=llm_result,
        )
    )

    risk_score = int(
        risk_result.get(
            "risk_score",
            0,
        )
    )

    risk_score = max(
        0,
        min(100, risk_score),
    )

    # ========================================================
    # 11. CLASSIFICATION
    # ========================================================

    classification = classify_message(
        risk_score=risk_score,
        content_analysis=content_result,
        attachment_analysis=(
            attachment_result
        ),
    )

    # ========================================================
    # 12. POLICY DECISION
    # ========================================================

    policy_result = (
        determine_policy_decision(
            classification=classification,
            risk_score=risk_score,
        )
    )

    # ========================================================
    # 13. NOTIFICATION DECISION
    # ========================================================

    notification_result = (
        determine_notification(
            classification=classification,
            policy_decision=(
                policy_result[
                    "policy_decision"
                ]
            ),
            risk_score=risk_score,
        )
    )

    # ========================================================
    # 14. SEVERITY
    # ========================================================

    severity = determine_severity(
        classification
    )

    # ========================================================
    # 15. REASON
    # ========================================================

    reason = generate_reason(
        classification=classification,
        sender_analysis=sender_result,
        content_analysis=content_result,
        url_analysis=url_result,
        attachment_analysis=(
            attachment_result
        ),
        threat_intelligence=(
            threat_intelligence_result
        ),
    )

    # ========================================================
    # 16. CONFIDENCE
    # ========================================================

    confidence = min(
        99.0,
        60.0 + (
            risk_score * 0.39
        ),
    )

    # ========================================================
    # 17. FINAL RESULT
    # ========================================================

    return {
        "classification": classification,

        "risk_score": risk_score,

        "risk_analysis": risk_result,

        "policy_decision": (
            policy_result[
                "policy_decision"
            ]
        ),

        "policy_analysis": policy_result,

        "notification": notification_result,

        "confidence": round(
            confidence,
            2,
        ),

        "severity": severity,

        "reason": reason,

        "recommended_action": (
            policy_result[
                "policy_decision"
            ]
        ),

        "human_review_required": (
            policy_result[
                "human_review_required"
            ]
        ),

        "notification_required": (
            notification_result[
                "should_notify"
            ]
        ),

        "notification_level": (
            notification_result[
                "priority"
            ]
        ),

        "sender_analysis": sender_result,

        "content_analysis": content_result,

        "url_analysis": url_result,

        "attachment_analysis": (
            attachment_result
        ),

        "threat_intelligence": (
            threat_intelligence_result
        ),

        "llm_analysis": llm_result,

        "urls": detected_urls,

        "attachments": (
            detected_attachments
        ),

        "pipeline": [
            "NORMALIZATION",
            "SENDER_ANALYSIS",
            "CONTENT_ANALYSIS",
            "URL_ANALYSIS",
            "ATTACHMENT_ANALYSIS",
            "THREAT_INTELLIGENCE",
            "LLM_ANALYSIS",
            "CONTEXTUAL_RISK_ENGINE",
            "CLASSIFICATION",
            "POLICY_DECISION",
            "NOTIFICATION_DECISION",
        ],
    }
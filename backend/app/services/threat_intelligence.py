"""
Cyberary-AI Threat Intelligence Service

Defensive threat-intelligence layer for the
Communication Security Gateway.

This module performs local/static reputation checks
without requiring external API keys.
"""

import ipaddress
from typing import Any, Dict, List
from urllib.parse import urlparse


# Known high-risk/suspicious indicators for local demo analysis.
# These are intentionally generic test indicators and are NOT
# intended to represent a production threat-intelligence feed.

SUSPICIOUS_TLDS = {
    ".click",
    ".top",
    ".xyz",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
}

SUSPICIOUS_DOMAIN_TERMS = {
    "verify-account",
    "account-verification",
    "security-alert",
    "password-reset",
    "login-confirm",
    "secure-login",
    "credential-check",
}


def normalize_domain(domain: str) -> str:
    """Normalize a domain name."""

    domain = (domain or "").strip().lower()

    if domain.startswith("www."):
        domain = domain[4:]

    return domain


def extract_domain_from_url(url: str) -> str:
    """Extract hostname from a URL."""

    try:
        parsed = urlparse(url)

        return normalize_domain(
            parsed.hostname or ""
        )

    except Exception:
        return ""


def is_ip_address(value: str) -> bool:
    """Check whether a value is an IP address."""

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


def analyze_domain(domain: str) -> Dict[str, Any]:
    """
    Perform local reputation analysis on a domain.
    """

    domain = normalize_domain(domain)

    result = {
        "domain": domain,
        "reputation": "UNKNOWN",
        "risk_points": 0,
        "signals": [],
    }

    if not domain:
        result["reputation"] = "INVALID"
        result["risk_points"] = 20
        result["signals"].append(
            "Domain could not be determined"
        )
        return result

    # Direct IP URLs can be suspicious in phishing scenarios.
    if is_ip_address(domain):
        result["reputation"] = "SUSPICIOUS"
        result["risk_points"] += 25
        result["signals"].append(
            "URL uses an IP address instead of a domain"
        )

    # Suspicious TLD check.
    if any(
        domain.endswith(tld)
        for tld in SUSPICIOUS_TLDS
    ):
        result["reputation"] = "SUSPICIOUS"
        result["risk_points"] += 20
        result["signals"].append(
            "Domain uses a suspicious TLD"
        )

    # Security-themed deceptive domain names.
    for term in SUSPICIOUS_DOMAIN_TERMS:
        if term in domain:
            result["reputation"] = "SUSPICIOUS"
            result["risk_points"] += 20
            result["signals"].append(
                f"Domain contains suspicious term: {term}"
            )

    # Very long domains can indicate obfuscation.
    if len(domain) > 60:
        result["reputation"] = "SUSPICIOUS"
        result["risk_points"] += 10
        result["signals"].append(
            "Unusually long domain name"
        )

    if not result["signals"]:
        result["reputation"] = "NO_KNOWN_THREAT"

    return result


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Analyze a single URL using local threat-intelligence rules.
    """

    result = {
        "url": url,
        "domain": "",
        "reputation": "UNKNOWN",
        "risk_points": 0,
        "signals": [],
    }

    try:
        parsed = urlparse(url)

        if parsed.scheme not in {
            "http",
            "https",
        }:
            result["reputation"] = "SUSPICIOUS"
            result["risk_points"] += 15
            result["signals"].append(
                "Unsupported or unusual URL scheme"
            )

        domain = normalize_domain(
            parsed.hostname or ""
        )

        result["domain"] = domain

        domain_result = analyze_domain(domain)

        result["reputation"] = domain_result[
            "reputation"
        ]

        result["risk_points"] += domain_result[
            "risk_points"
        ]

        result["signals"].extend(
            domain_result["signals"]
        )

        # HTTP is weaker than HTTPS.
        if parsed.scheme == "http":
            result["risk_points"] += 10
            result["signals"].append(
                "URL does not use HTTPS"
            )

        # URL username component can be abused for deception.
        if parsed.username:
            result["risk_points"] += 20
            result["reputation"] = "SUSPICIOUS"
            result["signals"].append(
                "URL contains a username component"
            )

    except Exception:
        result["reputation"] = "INVALID"
        result["risk_points"] += 20
        result["signals"].append(
            "URL parsing failed"
        )

    result["risk_points"] = min(
        100,
        result["risk_points"],
    )

    return result


def analyze_urls(
    urls: List[str],
) -> Dict[str, Any]:
    """
    Analyze all URLs found in a communication.
    """

    urls = urls or []

    results = [
        analyze_url(url)
        for url in urls
    ]

    total_risk = sum(
        item["risk_points"]
        for item in results
    )

    suspicious_count = sum(
        1
        for item in results
        if item["reputation"] in {
            "SUSPICIOUS",
            "MALICIOUS",
        }
    )

    if suspicious_count > 0:
        overall_reputation = "SUSPICIOUS"

    elif results:
        overall_reputation = "NO_KNOWN_THREAT"

    else:
        overall_reputation = "NO_URLS"

    return {
        "provider": "LOCAL_RULE_ENGINE",
        "status": "AVAILABLE",
        "total_urls": len(urls),
        "suspicious_urls": suspicious_count,
        "overall_reputation": overall_reputation,
        "risk_points": min(
            100,
            total_risk,
        ),
        "results": results,
    }


def analyze_sender_reputation(
    sender: str,
) -> Dict[str, Any]:
    """
    Basic sender-domain reputation analysis.
    """

    sender = (sender or "").strip().lower()

    result = {
        "sender": sender,
        "domain": "",
        "reputation": "UNKNOWN",
        "risk_points": 0,
        "signals": [],
    }

    if "@" not in sender:
        result["reputation"] = "INVALID"
        result["risk_points"] = 20
        result["signals"].append(
            "Sender does not contain a valid domain"
        )
        return result

    domain = normalize_domain(
        sender.rsplit("@", 1)[1]
    )

    result["domain"] = domain

    domain_result = analyze_domain(domain)

    result["reputation"] = domain_result[
        "reputation"
    ]

    result["risk_points"] = domain_result[
        "risk_points"
    ]

    result["signals"] = domain_result[
        "signals"
    ]

    return result


def get_threat_intelligence(
    sender: str,
    urls: List[str] | None = None,
) -> Dict[str, Any]:
    """
    Main Threat Intelligence entry point.

    Combines sender and URL intelligence.
    """

    sender_result = analyze_sender_reputation(
        sender
    )

    url_result = analyze_urls(
        urls or []
    )

    combined_risk = (
        sender_result["risk_points"]
        + url_result["risk_points"]
    )

    combined_risk = min(
        100,
        combined_risk,
    )

    if (
        sender_result["reputation"]
        in {"SUSPICIOUS", "MALICIOUS"}
        or url_result["overall_reputation"]
        in {"SUSPICIOUS", "MALICIOUS"}
    ):
        overall = "SUSPICIOUS"

    elif combined_risk == 0:
        overall = "NO_KNOWN_THREAT"

    else:
        overall = "LOW_RISK"

    return {
        "provider": "LOCAL_RULE_ENGINE",
        "status": "AVAILABLE",
        "overall_reputation": overall,
        "risk_points": combined_risk,
        "sender": sender_result,
        "urls": url_result,
    }
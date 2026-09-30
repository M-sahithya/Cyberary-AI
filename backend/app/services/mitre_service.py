"""
MITRE ATT&CK Enterprise Matrix Service
Provides technique taxonomy, tactic classification, and dynamic mappings for security events.
"""

from typing import List, Dict, Any, Optional

MITRE_ENTERPRISE_TACTICS = [
    {"id": "TA0001", "name": "Initial Access", "description": "Techniques to gain an initial foothold."},
    {"id": "TA0002", "name": "Execution", "description": "Techniques that result in adversary-controlled code running."},
    {"id": "TA0003", "name": "Persistence", "description": "Techniques adversaries use to keep access across restarts."},
    {"id": "TA0004", "name": "Privilege Escalation", "description": "Techniques to gain higher-level permissions."},
    {"id": "TA0005", "name": "Defense Evasion", "description": "Techniques adversaries use to avoid detection."},
    {"id": "TA0006", "name": "Credential Access", "description": "Techniques for stealing credentials like passwords."},
    {"id": "TA0007", "name": "Discovery", "description": "Techniques to gain knowledge about the system and network."},
    {"id": "TA0008", "name": "Lateral Movement", "description": "Techniques to enter and control remote systems."},
    {"id": "TA0009", "name": "Collection", "description": "Techniques to gather data of interest."},
    {"id": "TA0011", "name": "Command and Control", "description": "Techniques to communicate with controlled systems."},
]

MITRE_TECHNIQUES_CATALOG = [
    {
        "technique_id": "T1110.001",
        "name": "Password Guessing / Brute Force",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may systematically guess passwords to attempt authentication into target accounts.",
        "detection_count": 14,
        "confidence": 0.94,
    },
    {
        "technique_id": "T1555",
        "name": "Credentials from Password Stores",
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "description": "Adversaries may search for common password storage locations such as /etc/shadow or keychains.",
        "detection_count": 9,
        "confidence": 0.91,
    },
    {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may attempt to get a listing of services running on hosts over the network.",
        "detection_count": 18,
        "confidence": 0.88,
    },
    {
        "technique_id": "T1059.004",
        "name": "Unix Shell Execution",
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "description": "Adversaries may abuse Unix shells (/bin/sh, /bin/bash) to execute arbitrary commands.",
        "detection_count": 22,
        "confidence": 0.96,
    },
    {
        "technique_id": "T1548.001",
        "name": "Setuid and Setgid Abuse",
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "description": "Adversaries may perform sudo / SUID privilege escalation to execute commands with root permissions.",
        "detection_count": 6,
        "confidence": 0.89,
    },
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "tactic_id": "TA0001",
        "description": "Adversaries may attempt to exploit a vulnerability in an Internet-facing computer program.",
        "detection_count": 8,
        "confidence": 0.85,
    },
    {
        "technique_id": "T1071.001",
        "name": "Web Protocols C2",
        "tactic": "Command and Control",
        "tactic_id": "TA0011",
        "description": "Adversaries may communicate using application layer protocols (HTTP/HTTPS) to avoid detection.",
        "detection_count": 5,
        "confidence": 0.82,
    },
    {
        "technique_id": "T1082",
        "name": "System Information Discovery",
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "description": "Adversaries may get detailed information about the operating system and hardware (uname, lsb_release).",
        "detection_count": 12,
        "confidence": 0.93,
    },
]


def get_all_tactics() -> List[Dict[str, Any]]:
    return MITRE_ENTERPRISE_TACTICS


def get_all_techniques() -> List[Dict[str, Any]]:
    return MITRE_TECHNIQUES_CATALOG


def get_technique_by_id(technique_id: str) -> Optional[Dict[str, Any]]:
    for tech in MITRE_TECHNIQUES_CATALOG:
        if tech["technique_id"].lower() == technique_id.lower():
            return tech
    return None

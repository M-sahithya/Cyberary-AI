"""
LLM Threat Intelligence Engine
Converts raw honeypot terminal logs, commands, and security alerts into human-readable attack intent
and maps techniques to MITRE ATT&CK using structured Pydantic validation.
"""

import json
import logging
import httpx
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from app.config.settings import settings

logger = logging.getLogger("cyberary.threat_agent")


class ThreatIntelOutput(BaseModel):
    """Structured output for LLM threat analysis."""
    intent: str = Field(..., description="High-level attacker intent summary")
    attack_stage: str = Field(default="Discovery", description="Stage in the cyber kill chain")
    mitre_tactic: str = Field(..., description="MITRE ATT&CK Tactic name")
    technique_id: str = Field(..., description="MITRE Technique ID, e.g. T1555")
    technique_name: str = Field(..., description="MITRE Technique Name")
    severity: str = Field(default="MEDIUM", description="CRITICAL | HIGH | MEDIUM | LOW")
    confidence: float = Field(default=0.88, ge=0.0, le=1.0)
    impact: str = Field(..., description="Potential impact on infrastructure")
    recommendation: str = Field(..., description="Defensive recommendation")


# Heuristic cybersecurity classifier for local fallback when external LLM is offline
HEURISTIC_RULESET = [
    {
        "keywords": ["/etc/shadow", "/etc/passwd", "unshadow", "john", "hashcat"],
        "intent": "Credential Store Extraction",
        "attack_stage": "Credential Access",
        "mitre_tactic": "Credential Access",
        "technique_id": "T1555",
        "technique_name": "Credentials from Password Stores",
        "severity": "CRITICAL",
        "confidence": 0.95,
        "impact": "High risk of password hash exfiltration and offline brute force cracking.",
        "recommendation": "Restrict read access on credential stores and rotate system administrative passwords.",
    },
    {
        "keywords": ["sudo -l", "sudo su", "pkexec", "su root", "chmod u+s", "gdb -p 1"],
        "intent": "Local Privilege Escalation Attempt",
        "attack_stage": "Privilege Escalation",
        "mitre_tactic": "Privilege Escalation",
        "technique_id": "T1548.001",
        "technique_name": "Setuid and Setgid Abuse",
        "severity": "CRITICAL",
        "confidence": 0.92,
        "impact": "Attacker attempting to gain root privileges from unprivileged session.",
        "recommendation": "Audit sudoers configuration, remove unneeded SUID bits, and restrict sudo access.",
    },
    {
        "keywords": ["nmap", "masscan", "nc -zv", "ping -c", "netstat", "ss -tuln", "arp -a"],
        "intent": "Internal Network & Port Reconnaissance",
        "attack_stage": "Discovery",
        "mitre_tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "severity": "MEDIUM",
        "confidence": 0.89,
        "impact": "Adversary mapping available internal IP services for targeted exploitation.",
        "recommendation": "Deploy internal network segmentation and monitor egress port probes.",
    },
    {
        "keywords": ["uname -a", "cat /etc/os-release", "lscpu", "id", "whoami", "hostname"],
        "intent": "System Environment & Kernel Profiling",
        "attack_stage": "Discovery",
        "mitre_tactic": "Discovery",
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "severity": "LOW",
        "confidence": 0.91,
        "impact": "Gathering OS version to select weaponized kernel exploits.",
        "recommendation": "Ensure kernel and packages are kept on supported LTS patches.",
    },
    {
        "keywords": ["curl http", "wget http", "bash -i >& /dev/tcp", "nc -e /bin/sh", "python -c 'import socket"],
        "intent": "Reverse Shell / Payload Download Execution",
        "attack_stage": "Execution",
        "mitre_tactic": "Execution",
        "technique_id": "T1059.004",
        "technique_name": "Unix Shell Execution",
        "severity": "CRITICAL",
        "confidence": 0.97,
        "impact": "Attacker attempting remote command-and-control foothold and interactive shell.",
        "recommendation": "Block unauthorized outbound TCP connections and inspect binary execution paths.",
    },
]


async def analyze_threat_event(
    command_or_event: str,
    source: str = "Honeypot",
    context: Optional[Dict[str, Any]] = None,
) -> ThreatIntelOutput:
    """
    Analyzes an attack command sequence or security log using Ollama/OpenAI or heuristic inference.
    """
    raw_text = command_or_event.strip()

    # 1. Try LLM Provider if configured and reachable
    if settings.LLM_PROVIDER == "ollama" and settings.OLLAMA_BASE_URL and "ollama:" not in settings.OLLAMA_BASE_URL:
        try:
            prompt = f"""You are Cyberary-AI's Threat Intelligence Engine.
Analyze this security event / shell command and return ONLY valid JSON matching this schema:
{{
  "intent": "High-level summary of attacker intent",
  "attack_stage": "Discovery|Initial Access|Execution|Persistence|Privilege Escalation|Credential Access",
  "mitre_tactic": "Tactic Name",
  "technique_id": "Technique ID (e.g. T1110)",
  "technique_name": "Technique Name",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "confidence": 0.92,
  "impact": "Impact explanation",
  "recommendation": "Remediation recommendation"
}}

Input Event: {raw_text}
Source: {source}
"""
            async with httpx.AsyncClient(timeout=0.8) as client:
                res = await client.post(
                    f"{settings.OLLAMA_BASE_URL}/api/generate",
                    json={
                        "model": settings.LLM_MODEL,
                        "prompt": prompt,
                        "stream": False,
                        "format": "json",
                    },
                )
                if res.status_code == 200:
                    resp_json = res.json()
                    response_text = resp_json.get("response", "{}")
                    parsed = json.loads(response_text)
                    return ThreatIntelOutput(**parsed)
        except Exception:
            pass

    # 2. Heuristic Rule Classification (Deterministic & 100% Reliable for Demo)
    text_lower = raw_text.lower()
    for rule in HEURISTIC_RULESET:
        for kw in rule["keywords"]:
            if kw.lower() in text_lower:
                return ThreatIntelOutput(
                    intent=rule["intent"],
                    attack_stage=rule["attack_stage"],
                    mitre_tactic=rule["mitre_tactic"],
                    technique_id=rule["technique_id"],
                    technique_name=rule["technique_name"],
                    severity=rule["severity"],
                    confidence=rule["confidence"],
                    impact=rule["impact"],
                    recommendation=rule["recommendation"],
                )

    # 3. Default Generic Classification
    return ThreatIntelOutput(
        intent="Unclassified Suspicious Terminal Activity",
        attack_stage="Execution",
        mitre_tactic="Execution",
        technique_id="T1059.004",
        technique_name="Unix Shell Execution",
        severity="MEDIUM",
        confidence=0.82,
        impact="Command executed in isolated decoy environment.",
        recommendation="Monitor session sequence and verify user permissions.",
    )

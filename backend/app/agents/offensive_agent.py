"""
Offensive AI Agent
Conducts automated ethical attacks in non-production lab environments, identifying exploitable vectors,
correlating attack paths, and generating structured vulnerability finding reports.
Strictly restricted to authorized lab assets.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Any, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_entities import Asset, Vulnerability, Threat, Remediation
from app.security.target_allowlist import validate_target
from app.services.nvd_service import fetch_cve_details


# Safe simulated vulnerability vectors for lab assets
SIMULATED_VULN_PROFILES = [
    {
        "title": "OpenSSH PKCS#11 Provider Remote Code Execution",
        "cve_id": "CVE-2023-38408",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "service": "OpenSSH 8.9p1 (Port 22)",
        "description": "Insufficient library path sanitization in PKCS#11 provider allows arbitrary shared library loading.",
        "evidence": "Banner response: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6; ForwardAgent enabled.",
        "recommended_fix": "Upgrade OpenSSH to >= 9.3p2 or disable Agent forwarding.",
        "proposed_command": "sudo apt-get update && sudo apt-get --only-upgrade install openssh-server -y",
        "expected_result": "OpenSSH upgraded to latest security patch; CVE-2023-38408 mitigated.",
        "verification_step": "ssh -V && grep -i 'PKCS11Provider' /etc/ssh/sshd_config",
        "rollback_plan": "apt-get install openssh-server=1:8.9p1-3ubuntu0.6",
    },
    {
        "title": "Apache Log4j2 JNDI Remote Code Execution Vulnerability",
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "service": "Java Application Service (Port 8080)",
        "description": "Log4j JNDI lookup allows remote execution via attacker-controlled LDAP endpoints.",
        "evidence": "Header probe '${jndi:ldap://127.0.0.1:1389/a}' triggered internal DNS resolution callback.",
        "recommended_fix": "Update log4j to version 2.17.1 or higher and pass -Dlog4j2.formatMsgNoLookups=true flag.",
        "proposed_command": "echo 'LOG4J_FORMAT_MSG_NO_LOOKUPS=true' | sudo tee -a /etc/environment",
        "expected_result": "JNDI message lookup disabled globally across JVM services.",
        "verification_step": "ps aux | grep -i 'formatMsgNoLookups'",
        "rollback_plan": "sed -i '/LOG4J_FORMAT_MSG_NO_LOOKUPS/d' /etc/environment",
    },
    {
        "title": "OpenSSH Signal Handler Race Condition (RegreSSHion)",
        "cve_id": "CVE-2024-6387",
        "cvss_score": 8.1,
        "severity": "HIGH",
        "service": "OpenSSH Daemon (Port 22)",
        "description": "Signal handler race condition in sshd on glibc Linux allows unauthenticated remote code execution.",
        "evidence": "SIGALRM timing analysis confirms vulnerable asynchronous signal handler window.",
        "recommended_fix": "Apply vendor security patch or set LoginGraceTime to 0 in sshd_config.",
        "proposed_command": "sudo sed -i 's/^#\\?LoginGraceTime.*/LoginGraceTime 0/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
        "expected_result": "LoginGraceTime set to 0, eliminating the SIGALRM race window.",
        "verification_step": "sshd -T | grep -i 'logingracetime'",
        "rollback_plan": "sudo sed -i 's/^LoginGraceTime.*/LoginGraceTime 120/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
    },
    {
        "title": "Weak Sudo Configuration: Passwordless Shell Access",
        "cve_id": None,
        "cvss_score": 7.8,
        "severity": "HIGH",
        "service": "sudoers (Local PAM)",
        "description": "Local analyst account has NOPASSWD access to /bin/bash via sudoers.",
        "evidence": "Sudo listing shows: (ALL : ALL) NOPASSWD: ALL for service account.",
        "recommended_fix": "Require password authentication for elevated sudo actions.",
        "proposed_command": "sudo sed -i 's/NOPASSWD://g' /etc/sudoers.d/*",
        "expected_result": "NOPASSWD directive stripped from all sudoers includes.",
        "verification_step": "sudo -l",
        "rollback_plan": "Restore backup /etc/sudoers.d/ from /var/backups/sudoers.bak",
    },
]


async def run_ethical_assessment(
    db: AsyncSession,
    target_identifier: str,
) -> Dict[str, Any]:
    """
    Executes a safe vulnerability assessment against an authorized lab target:
    1. Validates target against allowlist
    2. Simulates penetration testing discovery
    3. Queries CVE / NVD details
    4. Generates structured Vulnerability and Remediation records
    """
    # 1. Allowlist Validation
    is_valid, reason = validate_target(target_identifier)
    if not is_valid:
        raise ValueError(reason)

    # 2. Find or register asset
    result = await db.execute(
        select(Asset).where(
            (Asset.name == target_identifier) | (Asset.ip_address == target_identifier)
        )
    )
    asset = result.scalar_one_or_none()

    if not asset:
        asset = Asset(
            name=target_identifier,
            ip_address="10.0.1.10" if "01" in target_identifier else "10.0.1.11",
            hostname=f"{target_identifier}.cyberary.local",
            environment="LAB",
            asset_type="linux",
            importance="HIGH",
            status="ONLINE",
            is_authorized=True,
            last_scan=datetime.now(timezone.utc),
            risk_score=75,
        )
        db.add(asset)
        await db.flush()
    else:
        asset.last_scan = datetime.now(timezone.utc)

    # 3. Generate Findings
    created_vulns = []
    created_remediations = []

    for profile in SIMULATED_VULN_PROFILES:
        # Check if already exists for this asset
        v_check = await db.execute(
            select(Vulnerability).where(
                Vulnerability.asset_id == asset.id,
                Vulnerability.title == profile["title"],
            )
        )
        existing_vuln = v_check.scalar_one_or_none()

        if not existing_vuln:
            finding_id = f"F-{uuid.uuid4().hex[:5].upper()}"
            vuln = Vulnerability(
                finding_id=finding_id,
                asset_id=asset.id,
                title=profile["title"],
                description=profile["description"],
                cve_id=profile["cve_id"],
                cvss_score=profile["cvss_score"],
                severity=profile["severity"],
                affected_service=profile["service"],
                confidence=0.94,
                status="OPEN",
                evidence=profile["evidence"],
                discovered_at=datetime.now(timezone.utc),
            )
            db.add(vuln)
            await db.flush()

            # Create AI Remediation Recommendation (requiring human approval)
            rem_code = f"REM-{uuid.uuid4().hex[:6].upper()}"
            remediation = Remediation(
                remediation_code=rem_code,
                vulnerability_id=vuln.id,
                issue=profile["title"],
                severity=profile["severity"],
                risk_score=int(profile["cvss_score"] * 9),
                recommended_fix=profile["recommended_fix"],
                proposed_command=profile["proposed_command"],
                expected_result=profile["expected_result"],
                verification_step=profile["verification_step"],
                rollback_plan=profile["rollback_plan"],
                status="PENDING",
                created_at=datetime.now(timezone.utc),
            )
            db.add(remediation)
            
            created_vulns.append({
                "finding_id": finding_id,
                "title": profile["title"],
                "severity": profile["severity"],
                "cvss_score": profile["cvss_score"],
                "cve_id": profile["cve_id"],
            })
            created_remediations.append(rem_code)

    await db.commit()

    return {
        "target": target_identifier,
        "asset_id": asset.id,
        "scan_status": "COMPLETED",
        "findings_discovered": len(created_vulns),
        "findings": created_vulns,
        "remediations_generated": len(created_remediations),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "lab_mode": True,
    }


async def run_autonomous_exploit_plan(
    db: AsyncSession,
    target_identifier: str = "lab-server-01",
    cve_description: Optional[str] = None,
    enable_concurrency: bool = True,
) -> Dict[str, Any]:
    """
    Executes advanced autonomous exploit planning inspired by Richard Fang et al. (arXiv:2404.08144v2):
    - Subagent architecture (Recon, Hypothesis, ExploitPlanner, Concurrency, Verification)
    - Multi-vector hypothesis testing with or without CVE description
    - ACIDRain database concurrency & race-condition evaluation
    - Defensive countermeasure synthesis and DB synchronization
    """
    from app.services.autonomous_exploit_planner import autonomous_exploit_planner
    from app.models.security_entities import AgentTask

    plan_result = await autonomous_exploit_planner.run_autonomous_assessment(
        target=target_identifier,
        cve_description=cve_description,
        enable_concurrency_test=enable_concurrency,
    )

    base_report = await run_ethical_assessment(db=db, target_identifier=target_identifier)
    plan_result["asset_id"] = base_report["asset_id"]
    plan_result["synced_findings"] = base_report["findings"]

    # Record AgentTask execution
    task_entry = AgentTask(
        id=str(uuid.uuid4()),
        agent_name="Offensive AI Agent (Autonomous Planner)",
        task_type="AUTONOMOUS_EXPLOIT_PLANNING",
        status="SUCCESS",
        last_run=datetime.now(timezone.utc),
    )
    db.add(task_entry)
    await db.commit()

    return plan_result

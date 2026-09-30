"""
Dynamic AI Honeypot Agent
Emulates interactive Linux shells, maintains session context, records terminal commands,
and integrates with the Threat Intelligence pipeline.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.security_entities import HoneypotSession, TerminalEvent, Threat, MitreTechnique, Asset
from app.agents.threat_agent import analyze_threat_event
from app.services.generative_honeypot import (
    generative_honeypot_engine,
    stateful_fallback_emulate,
    HoneypotSessionState,
)


COMMAND_EMULATION_MAP = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": "Linux lab-honeypot-01 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:49:32 UTC 2023 x86_64 GNU/Linux",
    "hostname": "lab-honeypot-01.cyberary.local",
    "pwd": "/root",
    "ls": "backup.tar.gz  config.yaml  scripts  ssh_keys",
    "ls -la": "drwx------  4 root root 4096 Jan 15 10:00 .\ndrwxr-xr-x 19 root root 4096 Jan 10 08:30 ..\n-rw-------  1 root root  512 Jan 15 09:45 .bash_history\n-rw-r--r--  1 root root  220 Jan 10 08:30 .bash_logout\n-rw-r--r--  1 root root 3771 Jan 10 08:30 .bashrc\n-rw-------  1 root root 1024 Jan 15 10:01 backup.tar.gz\n-rw-r--r--  1 root root  340 Jan 14 12:20 config.yaml",
    "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\nsys:x:3:3:sys:/dev:/usr/sbin/nologin\nsync:x:4:65534:sync:/bin:/bin/sync\nsshd:x:110:65534::/run/sshd:/usr/sbin/nologin\nanalyst:x:1000:1000:SOC Analyst,,,:/home/analyst:/bin/bash",
    "cat /etc/shadow": "root:$6$rounds=656000$s9K8fJ2a$9vQ7W5p2J...:19738:0:99999:7:::\nanalyst:$6$rounds=656000$h8N2mK1p$0xL9...:19738:0:99999:7:::",
    "sudo -l": "Matching Defaults entries for root on lab-honeypot-01:\n    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\nUser root may run the following commands on lab-honeypot-01:\n    (ALL : ALL) ALL",
    "netstat -tuln": "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address           Foreign Address         State\ntcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\ntcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\ntcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN",
    "ps aux": "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot           1  0.0  0.1 168344 11244 ?        Ss   09:00   0:01 /sbin/init\nroot         412  0.0  0.0  72296  3420 ?        Ss   09:00   0:00 /usr/sbin/sshd -D\nroot         580  0.0  0.2 220140 18450 ?        S    09:01   0:02 python3 decoy_service.py",
}


def emulate_command_response(cmd: str) -> str:
    """Returns realistic isolated Linux shell output for honeypot commands (preserved for compatibility)."""
    state = HoneypotSessionState(session_id="legacy-emulate", cwd="/root")
    return stateful_fallback_emulate(state, cmd)


async def record_honeypot_interaction(
    db: AsyncSession,
    session_id: str,
    command: str,
    attacker_ip: str = "10.0.1.105",
) -> Dict[str, Any]:
    """
    Processes an attacker shell command inside the Generative AI Honeypot:
    1. Uses shelLM generative engine (Ollama with per-session state context & deterministic fallback)
    2. Runs Threat Intelligence LLM analysis
    3. Updates MITRE technique detection counts
    4. Saves Terminal Event, session metadata & Threat record to Database
    """
    # Find session
    result = await db.execute(
        select(HoneypotSession).where(HoneypotSession.id == session_id)
    )
    session = result.scalar_one_or_none()

    if not session:
        # Create session if needed
        session = HoneypotSession(
            id=session_id,
            session_code=f"SESS-{session_id[:8].upper()}",
            attacker_ip=attacker_ip,
            username="root",
            status="ACTIVE",
            command_count=0,
            session_metadata={},
        )
        db.add(session)
        await db.flush()

    # Generate realistic shell response via Generative AI Honeypot Engine
    shell_res = await generative_honeypot_engine.execute_shell_command(
        session_id=session.id,
        command=command,
        attacker_ip=attacker_ip,
        existing_metadata=session.session_metadata,
    )
    response_text = shell_res.get("response", "")
    session_metadata = shell_res.get("session_metadata", {})
    current_cwd = shell_res.get("cwd", "/root")
    engine_used = shell_res.get("engine_used", "deterministic_fallback")

    # Analyze with Threat Intelligence Agent
    intel = await analyze_threat_event(command, source="Honeypot")

    # Record terminal event with context
    term_evt = TerminalEvent(
        session_id=session.id,
        command=command,
        response=response_text,
        intent=intel.intent,
        mitre_technique=intel.technique_id,
        mitre_tactic=intel.mitre_tactic,
        severity=intel.severity,
        event_metadata={
            "cwd": current_cwd,
            "engine_used": engine_used,
            "suspicion_score": shell_res.get("suspicion_score", shell_res.get("intelligence", {}).get("suspicion_score", 0.0)),
            "suspicion_level": shell_res.get("suspicion_level", shell_res.get("intelligence", {}).get("suspicion_level", "LOW")),
            "human_vs_bot": shell_res.get("human_vs_bot", shell_res.get("intelligence", {}).get("human_vs_bot", {})),
            "planted_breadcrumbs": shell_res.get("planted_breadcrumbs", shell_res.get("intelligence", {}).get("planted_breadcrumbs", [])),
        },
        timestamp=datetime.now(timezone.utc),
    )
    db.add(term_evt)

    # Update session metrics and serialized session state
    session.command_count += 1
    session.threat_level = intel.severity
    session.session_metadata = session_metadata

    # Calculate risk score
    risk_mapping = {"CRITICAL": 95.0, "HIGH": 80.0, "MEDIUM": 50.0, "LOW": 25.0}
    calculated_risk = risk_mapping.get(intel.severity.upper(), 50.0)

    # Record threat event if CRITICAL / HIGH / MEDIUM
    threat_entry = Threat(
        event_id=f"EVT-HP-{uuid.uuid4().hex[:6].upper()}",
        title=f"{intel.intent}: `{command[:40]}`",
        source="Honeypot",
        severity=intel.severity,
        status="Active",
        risk_score=calculated_risk,
        mitre_technique=intel.technique_id,
        mitre_tactic=intel.mitre_tactic,
        intent=intel.intent,
        impact=intel.impact,
        confidence=intel.confidence,
        raw_payload=f"CMD: {command} | RESP: {response_text[:100]}",
        timestamp=datetime.now(timezone.utc),
    )
    db.add(threat_entry)

    # Update MITRE technique detection counter
    mitre_res = await db.execute(
        select(MitreTechnique).where(MitreTechnique.technique_id == intel.technique_id)
    )
    mitre_tech = mitre_res.scalar_one_or_none()
    if mitre_tech:
        mitre_tech.detection_count += 1
    else:
        new_mitre = MitreTechnique(
            technique_id=intel.technique_id,
            name=intel.technique_name,
            tactic=intel.mitre_tactic,
            description=intel.intent,
            detection_count=1,
            confidence=intel.confidence,
        )
        db.add(new_mitre)

    await db.commit()

    return {
        "session_id": session.id,
        "command": command,
        "response": response_text,
        "cwd": current_cwd,
        "engine_used": engine_used,
        "suspicion_score": shell_res.get("suspicion_score", shell_res.get("intelligence", {}).get("suspicion_score", 0.0)),
        "suspicion_level": shell_res.get("suspicion_level", shell_res.get("intelligence", {}).get("suspicion_level", "LOW")),
        "human_vs_bot": shell_res.get("human_vs_bot", shell_res.get("intelligence", {}).get("human_vs_bot", {})),
        "planted_breadcrumbs": shell_res.get("planted_breadcrumbs", shell_res.get("intelligence", {}).get("planted_breadcrumbs", [])),
        "intelligence": {
            "suspicion_score": shell_res.get("suspicion_score", shell_res.get("intelligence", {}).get("suspicion_score", 0.0)),
            "suspicion_level": shell_res.get("suspicion_level", shell_res.get("intelligence", {}).get("suspicion_level", "LOW")),
            "human_vs_bot": shell_res.get("human_vs_bot", shell_res.get("intelligence", {}).get("human_vs_bot", {})),
            "planted_breadcrumbs": shell_res.get("planted_breadcrumbs", shell_res.get("intelligence", {}).get("planted_breadcrumbs", [])),
        },
        "intent": intel.intent,
        "mitre_technique": intel.technique_id,
        "mitre_tactic": intel.mitre_tactic,
        "severity": intel.severity,
        "timestamp": term_evt.timestamp.isoformat(),
        "session_metadata": session_metadata,
    }

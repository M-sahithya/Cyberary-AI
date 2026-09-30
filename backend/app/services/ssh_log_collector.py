"""
CYBERARY-AI
Advanced SSH Security Log Collector / Parser

Features:
- SSH failed password detection
- Invalid user detection
- Connection reset detection
- Successful SSH authentication detection
- Pre-authentication disconnect detection
- Normal SSH disconnect detection
- Brute-force correlation
- Multi-user account enumeration detection
- Successful login after attack detection
- MITRE ATT&CK mapping
- Severity escalation
"""

import re
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Optional


# ============================================================
# CONFIGURATION
# ============================================================

BRUTE_FORCE_WINDOW_SECONDS = 60
BRUTE_FORCE_THRESHOLD = 5
MULTI_USER_THRESHOLD = 3


# ============================================================
# SSH REGEX PATTERNS
# ============================================================

SSH_FAILED_RE = re.compile(
    r"Failed\s+password\s+for\s+"
    r"(?:invalid\s+user\s+)?(\S+)\s+"
    r"from\s+(\S+)\s+"
    r"port\s+(\d+)",
    re.IGNORECASE,
)

SSH_INVALID_RE = re.compile(
    r"Invalid\s+user\s+(\S+)\s+"
    r"from\s+(\S+)\s+"
    r"port\s+(\d+)",
    re.IGNORECASE,
)

SSH_RESET_INVALID_RE = re.compile(
    r"Connection\s+reset\s+by\s+invalid\s+user\s+"
    r"(\S+)\s+"
    r"(\S+)\s+"
    r"port\s+(\d+)",
    re.IGNORECASE,
)

SSH_ACCEPTED_RE = re.compile(
    r"Accepted\s+"
    r"(password|publickey|keyboard-interactive/pam)\s+"
    r"for\s+(\S+)\s+"
    r"from\s+(\S+)\s+"
    r"port\s+(\d+)",
    re.IGNORECASE,
)

SSH_PREAUTH_DISCONNECT_RE = re.compile(
    r"Disconnected\s+from\s+"
    r"(?:invalid\s+user\s+)?(\S+)\s+"
    r"(\S+)\s+"
    r"port\s+(\d+).*preauth",
    re.IGNORECASE,
)

SSH_DISCONNECT_WITH_USER_RE = re.compile(
    r"Disconnected\s+from\s+"
    r"(?:invalid\s+user\s+)?(\S+)\s+"
    r"(\S+)\s+"
    r"port\s+(\d+)",
    re.IGNORECASE,
)

SSH_DISCONNECT_IP_ONLY_RE = re.compile(
    r"Disconnected\s+from\s+"
    r"(\S+)\s+"
    r"port\s+(\d+)",
    re.IGNORECASE,
)

# Sudo command execution pattern
# Example: 2026-09-25T05:24:07.448939+00:00 Ubuntu sudo: sahithya :  PWD=/home/sahithya ; USER=root ; COMMAND=/usr/bin/tail -n 15 /var/log/auth.log
SUDO_COMMAND_RE = re.compile(
    r"sudo:\s+(\S+)\s*:\s*(?:TTY=\S+\s*;\s*)?(?:PWD=\S+\s*;\s*)?USER=(\S+)\s*;\s*COMMAND=(.+)",
    re.IGNORECASE,
)

# SSH Exploit / Protocol Anomaly / Banner Exchange patterns (T1190)
SSH_BANNER_INVALID_RE = re.compile(
    r"banner\s+exchange:\s+Connection\s+from\s+(\S+)\s+port\s+(\d+):\s+invalid\s+format",
    re.IGNORECASE,
)

SSH_BAD_PROTOCOL_RE = re.compile(
    r"Bad\s+protocol\s+version\s+identification\s+(?:'[^']*'|\S+)\s+from\s+(\S+)\s+port\s+(\d+)",
    re.IGNORECASE,
)

SSH_PROTOCOL_ERROR_RE = re.compile(
    r"(?:Corrupted\s+MAC\s+on\s+input|kex\s+protocol\s+error|fatal:\s+kex_exchange_identification)\s+.*from\s+(\S+)\s+port\s+(\d+)",
    re.IGNORECASE,
)

ISO_TIMESTAMP_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))"
)


# ============================================================
# ATTACK HISTORY
# ============================================================

_ATTACK_HISTORY = defaultdict(deque)


# ============================================================
# EVENT BUILDER
# ============================================================

def _base_event(
    *,
    line: str,
    event_type: str,
    username: str,
    attacker_ip: str,
    port: int,
    technique: str,
    tactic: str,
    severity: str,
    intent: str,
    confidence: float,
    risk_score: Optional[float] = None,
    timestamp: Optional[datetime] = None,
) -> dict:

    if timestamp is None:
        ts_match = ISO_TIMESTAMP_RE.match(line)
        if ts_match:
            try:
                timestamp = datetime.fromisoformat(ts_match.group(1))
            except Exception:
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)

    if risk_score is None:
        sev_risk = {
            "CRITICAL": 95.0,
            "HIGH": 80.0,
            "MEDIUM": 50.0,
            "LOW": 25.0,
        }
        risk_score = sev_risk.get(severity, 50.0)

    return {
        "event_type": event_type,
        "username": username,
        "attacker_ip": attacker_ip,
        "source_port": port,
        "mitre_technique": technique,
        "mitre_tactic": tactic,
        "severity": severity,
        "intent": intent,
        "confidence": confidence,
        "risk_score": float(risk_score),
        "raw_payload": line,
        "timestamp": timestamp,
    }


# ============================================================
# CLEAN OLD EVENTS
# ============================================================

def _cleanup_history(attacker_ip: str, now: datetime) -> None:

    history = _ATTACK_HISTORY[attacker_ip]

    cutoff = now - timedelta(
        seconds=BRUTE_FORCE_WINDOW_SECONDS
    )

    while history and history[0]["timestamp"] < cutoff:
        history.popleft()


# ============================================================
# RECORD FAILED AUTHENTICATION
# ============================================================

def _record_failure(
    attacker_ip: str,
    username: str,
    event_type: str,
    timestamp: datetime,
) -> dict:

    history = _ATTACK_HISTORY[attacker_ip]

    history.append(
        {
            "timestamp": timestamp,
            "username": username,
            "event_type": event_type,
        }
    )

    _cleanup_history(attacker_ip, timestamp)

    failure_events = [
        item
        for item in history
        if item["event_type"]
        in {
            "SSH_AUTH_FAILURE",
            "SSH_INVALID_USER",
            "SSH_CONNECTION_RESET",
            "SSH_PREAUTH_DISCONNECT",
            "SSH_BRUTE_FORCE",
        }
    ]

    failure_count = len(failure_events)

    usernames = {
        item["username"]
        for item in failure_events
        if item.get("username")
    }

    multiple_user_attack = (
        len(usernames) >= MULTI_USER_THRESHOLD
    )

    brute_force = (
        failure_count >= BRUTE_FORCE_THRESHOLD
    )

    if brute_force and multiple_user_attack:

        severity = "CRITICAL"

        intent = (
            "Coordinated SSH Brute-Force Attack with "
            "Multiple Username Enumeration"
        )

    elif brute_force:

        severity = "CRITICAL"

        intent = "Repeated SSH Brute-Force Attack"

    elif multiple_user_attack:

        severity = "HIGH"

        intent = "SSH Account Enumeration Activity"

    else:

        severity = None
        intent = None

    return {
        "failure_count": failure_count,
        "unique_username_count": len(usernames),
        "brute_force_detected": brute_force,
        "multiple_user_attack": multiple_user_attack,
        "escalated_severity": severity,
        "correlated_intent": intent,
    }


# ============================================================
# APPLY CORRELATION
# ============================================================

def _apply_correlation(event: dict) -> dict:

    event_type = event.get("event_type")

    if event_type not in {
        "SSH_AUTH_FAILURE",
        "SSH_INVALID_USER",
        "SSH_CONNECTION_RESET",
        "SSH_PREAUTH_DISCONNECT",
    }:
        return event

    attacker_ip = event["attacker_ip"]
    username = event["username"]
    timestamp = event["timestamp"]

    correlation = _record_failure(
        attacker_ip=attacker_ip,
        username=username,
        event_type=event_type,
        timestamp=timestamp,
    )

    event.update(
        {
            "failure_count": correlation["failure_count"],
            "unique_username_count": correlation[
                "unique_username_count"
            ],
            "brute_force_detected": correlation[
                "brute_force_detected"
            ],
            "multiple_user_attack": correlation[
                "multiple_user_attack"
            ],
        }
    )

    if correlation["escalated_severity"]:

        event["severity"] = correlation["escalated_severity"]

        event["intent"] = correlation["correlated_intent"]

        event["confidence"] = max(
            float(event.get("confidence", 0.0)),
            0.98,
        )

        event["event_type"] = "SSH_BRUTE_FORCE"

    return event


# ============================================================
# SUCCESSFUL LOGIN CORRELATION
# ============================================================

def _correlate_success(event: dict) -> dict:

    attacker_ip = event["attacker_ip"]
    username = event["username"]
    timestamp = event["timestamp"]

    history = _ATTACK_HISTORY[attacker_ip]

    _cleanup_history(attacker_ip, timestamp)

    recent_failures = [
        item
        for item in history
        if item["event_type"]
        in {
            "SSH_AUTH_FAILURE",
            "SSH_INVALID_USER",
            "SSH_CONNECTION_RESET",
            "SSH_PREAUTH_DISCONNECT",
            "SSH_BRUTE_FORCE",
        }
    ]

    if recent_failures:

        usernames = {
            item["username"]
            for item in recent_failures
            if item.get("username")
        }

        failure_count = len(recent_failures)

        event["previous_failure_count"] = failure_count

        event["previous_unique_username_count"] = len(
            usernames
        )

        event["correlated_with_attack"] = True

        event["severity"] = "HIGH"

        event["intent"] = (
            "Successful SSH Authentication Following "
            "Recent Authentication Attack"
        )

        event["confidence"] = 0.99

        return event

    event["previous_failure_count"] = 0

    event["previous_unique_username_count"] = 0

    event["correlated_with_attack"] = False

    return event


# ============================================================
# SUDO COMMAND PARSER
# ============================================================

def _parse_sudo_command(line: str) -> Optional[dict]:
    """
    Parse sudo executions from /var/log/auth.log into corresponding
    MITRE ATT&CK techniques (T1555, T1046, T1059.004, T1548.001, T1190, T1071.001, T1082).
    """
    match = SUDO_COMMAND_RE.search(line)
    if not match:
        return None

    invoking_user, target_user, command_str = match.groups()
    command_str = command_str.strip()
    caller_ip = "192.168.56.103"

    # 1. T1555: Credentials from Password Stores
    if re.search(r"(?:/etc/shadow|/etc/gshadow|/etc/master\.passwd|unshadow|john\s+)", command_str, re.IGNORECASE):
        return _base_event(
            line=line,
            event_type="CREDENTIAL_STORE_ACCESS",
            username=invoking_user,
            attacker_ip=caller_ip,
            port=0,
            technique="T1555",
            tactic="Credential Access",
            severity="CRITICAL",
            intent="Sensitive Credential Store Read Attempt (/etc/shadow)",
            confidence=0.96,
            risk_score=92.0,
        )

    # 2. T1046: Network Service Discovery
    if re.search(r"(?:nmap|netstat|ss\s+|lsof\s+-i|arp-scan|masscan|tcpdump|/proc/net/tcp|/proc/net/udp|/etc/services|network_recon)", command_str, re.IGNORECASE):
        return _base_event(
            line=line,
            event_type="NETWORK_SERVICE_DISCOVERY",
            username=invoking_user,
            attacker_ip=caller_ip,
            port=0,
            technique="T1046",
            tactic="Discovery",
            severity="MEDIUM",
            intent="Network Service & Port Discovery Enumeration",
            confidence=0.90,
            risk_score=65.0,
        )

    # 3. T1059.004: Unix Shell Execution
    if re.search(r"(?:/bin/bash|/bin/sh|/bin/zsh|/bin/dash|su\s+-|bash\s+-c|sh\s+-c|bash_shell|shell_exec)", command_str, re.IGNORECASE):
        return _base_event(
            line=line,
            event_type="UNIX_SHELL_EXECUTION",
            username=invoking_user,
            attacker_ip=caller_ip,
            port=0,
            technique="T1059.004",
            tactic="Execution",
            severity="HIGH",
            intent="Privileged Interactive/Script Unix Shell Execution",
            confidence=0.95,
            risk_score=85.0,
        )

    # 4. T1548.001: Setuid and Setgid Abuse
    if re.search(r"(?:sudo\s+-[ls]|pkexec|find\s+.*-perm|chmod\s+[ug]\+s|/etc/sudoers|sudoers\.d)", command_str, re.IGNORECASE):
        return _base_event(
            line=line,
            event_type="SETUID_SUDO_ABUSE",
            username=invoking_user,
            attacker_ip=caller_ip,
            port=0,
            technique="T1548.001",
            tactic="Privilege Escalation",
            severity="HIGH",
            intent="Sudo / Setuid Privilege Escalation Probe",
            confidence=0.92,
            risk_score=80.0,
        )

    # 5. T1190: Exploit Public-Facing Application (in command payloads)
    if re.search(r"(?:exploit|cve-\d+|poc|metasploit|dirtycow)", command_str, re.IGNORECASE):
        return _base_event(
            line=line,
            event_type="EXPLOIT_APP_PROBE",
            username=invoking_user,
            attacker_ip=caller_ip,
            port=0,
            technique="T1190",
            tactic="Initial Access",
            severity="CRITICAL",
            intent="Exploit Execution / Vulnerability Payload Probe",
            confidence=0.94,
            risk_score=90.0,
        )

    # 6. T1071.001: Web Protocols C2
    if re.search(r"(?:curl[\s_]|wget[\s_]|python3?\s+-m\s+http|nc\s+|ncat\s+|c2_beacon|web_c2)", command_str, re.IGNORECASE):
        return _base_event(
            line=line,
            event_type="WEB_PROTOCOLS_C2",
            username=invoking_user,
            attacker_ip=caller_ip,
            port=0,
            technique="T1071.001",
            tactic="Command and Control",
            severity="MEDIUM",
            intent="Application-Layer Web Protocol Invocation (HTTP/HTTPS)",
            confidence=0.88,
            risk_score=60.0,
        )

    # 7. T1082: System Information Discovery
    if re.search(r"(?:uname\s+|lscpu|hostnamectl|lsb_release|/etc/os-release|cat\s+/proc/version|/proc/version)", command_str, re.IGNORECASE):
        return _base_event(
            line=line,
            event_type="SYSTEM_INFO_DISCOVERY",
            username=invoking_user,
            attacker_ip=caller_ip,
            port=0,
            technique="T1082",
            tactic="Discovery",
            severity="LOW",
            intent="System Architecture & OS Profile Discovery",
            confidence=0.92,
            risk_score=30.0,
        )

    return None


# ============================================================
# MAIN SSH PARSER
# ============================================================

def parse_ssh_log_line(line: str) -> Optional[dict]:

    if not line:
        return None

    line = line.strip()

    if not line:
        return None

    # Check sudo commands from /var/log/auth.log
    sudo_event = _parse_sudo_command(line)
    if sudo_event:
        return sudo_event

    # Exploit / Protocol Anomaly (T1190)
    match = SSH_BANNER_INVALID_RE.search(line)
    if match:
        attacker_ip, port = match.groups()
        return _base_event(
            line=line,
            event_type="EXPLOIT_APP_PROBE",
            username="unknown",
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1190",
            tactic="Initial Access",
            severity="CRITICAL",
            intent="Public-Facing SSH Protocol / Banner Exploit Probe",
            confidence=0.94,
            risk_score=90.0,
        )

    match = SSH_BAD_PROTOCOL_RE.search(line)
    if match:
        attacker_ip, port = match.groups()
        return _base_event(
            line=line,
            event_type="EXPLOIT_APP_PROBE",
            username="unknown",
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1190",
            tactic="Initial Access",
            severity="CRITICAL",
            intent="Bad Protocol Version / Exploit Banner Anomaly",
            confidence=0.94,
            risk_score=90.0,
        )

    match = SSH_PROTOCOL_ERROR_RE.search(line)
    if match:
        attacker_ip, port = match.groups()
        return _base_event(
            line=line,
            event_type="EXPLOIT_APP_PROBE",
            username="unknown",
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1190",
            tactic="Initial Access",
            severity="HIGH",
            intent="SSH Key Exchange Protocol Corruption",
            confidence=0.90,
            risk_score=85.0,
        )

    # ========================================================
    # FAILED PASSWORD
    # ========================================================

    match = SSH_FAILED_RE.search(line)

    if match:

        username, attacker_ip, port = match.groups()

        event = _base_event(
            line=line,
            event_type="SSH_AUTH_FAILURE",
            username=username,
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1110.001",
            tactic="Credential Access",
            severity="HIGH",
            intent="Automated Password Guessing",
            confidence=0.94,
        )

        return _apply_correlation(event)

    # ========================================================
    # INVALID USER
    # ========================================================

    match = SSH_INVALID_RE.search(line)

    if match:

        username, attacker_ip, port = match.groups()

        event = _base_event(
            line=line,
            event_type="SSH_INVALID_USER",
            username=username,
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1110.001",
            tactic="Credential Access",
            severity="HIGH",
            intent="Password Guessing / Invalid Account Discovery",
            confidence=0.91,
        )

        return _apply_correlation(event)

    # ========================================================
    # CONNECTION RESET
    # ========================================================

    match = SSH_RESET_INVALID_RE.search(line)

    if match:

        username, attacker_ip, port = match.groups()

        event = _base_event(
            line=line,
            event_type="SSH_CONNECTION_RESET",
            username=username,
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1110.001",
            tactic="Credential Access",
            severity="MEDIUM",
            intent="Invalid Account Authentication Attempt",
            confidence=0.88,
        )

        return _apply_correlation(event)

    # ========================================================
    # SUCCESSFUL SSH LOGIN
    # ========================================================

    match = SSH_ACCEPTED_RE.search(line)

    if match:

        auth_method, username, attacker_ip, port = match.groups()

        event = _base_event(
            line=line,
            event_type="SSH_AUTH_SUCCESS",
            username=username,
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1078",
            tactic="Defense Evasion",
            severity="MEDIUM",
            intent=(
                f"Successful SSH Authentication via "
                f"{auth_method}"
            ),
            confidence=0.99,
        )

        return _correlate_success(event)

    # ========================================================
    # PRE-AUTH DISCONNECT
    # ========================================================

    match = SSH_PREAUTH_DISCONNECT_RE.search(line)

    if match:

        username, attacker_ip, port = match.groups()

        event = _base_event(
            line=line,
            event_type="SSH_PREAUTH_DISCONNECT",
            username=username,
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1110.001",
            tactic="Credential Access",
            severity="MEDIUM",
            intent="SSH Pre-Authentication Connection Termination",
            confidence=0.84,
        )

        return _apply_correlation(event)

    # ========================================================
    # DISCONNECT WITH USER
    # ========================================================

    match = SSH_DISCONNECT_WITH_USER_RE.search(line)

    if match:

        username, attacker_ip, port = match.groups()

        return _base_event(
            line=line,
            event_type="SSH_DISCONNECT",
            username=username,
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1078",
            tactic="Defense Evasion",
            severity="LOW",
            intent="SSH Session Termination",
            confidence=0.80,
        )

    # ========================================================
    # DISCONNECT WITHOUT USER
    # ========================================================

    match = SSH_DISCONNECT_IP_ONLY_RE.search(line)

    if match:

        attacker_ip, port = match.groups()

        return _base_event(
            line=line,
            event_type="SSH_DISCONNECT",
            username="unknown",
            attacker_ip=attacker_ip,
            port=int(port),
            technique="T1078",
            tactic="Defense Evasion",
            severity="LOW",
            intent="SSH Session Termination",
            confidence=0.80,
        )

    # ========================================================
    # UNKNOWN
    # ========================================================

    return None


# ============================================================
# ATTACK HISTORY RESET
# ============================================================

def clear_attack_history() -> None:

    _ATTACK_HISTORY.clear()


# ============================================================
# STATISTICS
# ============================================================

def get_attack_statistics() -> dict:

    return {
        "tracked_source_ips": len(_ATTACK_HISTORY),
        "tracked_events": sum(
            len(events)
            for events in _ATTACK_HISTORY.values()
        ),
        "window_seconds": BRUTE_FORCE_WINDOW_SECONDS,
        "brute_force_threshold": BRUTE_FORCE_THRESHOLD,
        "multi_user_threshold": MULTI_USER_THRESHOLD,
    }


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":

    clear_attack_history()

    test_lines = [

        "Failed password for invalid user admin "
        "from 192.168.56.1 port 45678 ssh2",

        "Failed password for sahithya "
        "from 192.168.56.1 port 45679 ssh2",

        "Invalid user fakeuser "
        "from 192.168.56.1 port 45680",

        "Connection reset by invalid user fakeuser "
        "192.168.56.1 port 56858 [preauth]",

        "Failed password for root "
        "from 192.168.56.1 port 45682 ssh2",

        "Accepted password for sahithya "
        "from 192.168.56.1 port 45681 ssh2",

        "Disconnected from invalid user admin "
        "192.168.56.1 port 45683 [preauth]",

        "Disconnected from 192.168.56.1 port 45684",

        "pam_unix(sshd:session): "
        "session opened for user sahithya",
    ]

    print()
    print("=" * 80)
    print("CYBERARY-AI ADVANCED SSH PARSER TEST")
    print("=" * 80)

    for index, line in enumerate(test_lines, start=1):

        print()
        print("-" * 80)
        print(f"TEST #{index}")
        print("-" * 80)

        print("RAW:")
        print(line)

        result = parse_ssh_log_line(line)

        print()
        print("PARSED:")

        if result is None:

            print("None")

        else:

            for key, value in result.items():
                print(f"{key}: {value}")

    print()
    print("=" * 80)
    print("ATTACK CORRELATION STATISTICS")
    print("=" * 80)

    print(get_attack_statistics())

    print()
    print("=" * 80)
    print("TEST COMPLETE")
    print("=" * 80)
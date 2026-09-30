"""
SSH Parser and Correlation Unit Tests
Tests all 10 required scenarios:
1. failed password
2. invalid user
3. connection reset
4. multiple usernames
5. repeated failures (brute force)
6. successful login
7. successful login after failures
8. pre-auth disconnect
9. normal disconnect
10. unrelated pam/session log
"""

import pytest
from app.services.ssh_log_collector import (
    parse_ssh_log_line,
    clear_attack_history,
    get_attack_statistics,
)


@pytest.fixture(autouse=True)
def clean_history():
    """Reset attack correlation state before every test."""
    clear_attack_history()
    yield
    clear_attack_history()


def test_scenario_1_failed_password():
    line = "Failed password for sahithya from 192.168.56.1 port 52345 ssh2"
    event = parse_ssh_log_line(line)

    assert event is not None
    assert event["event_type"] == "SSH_AUTH_FAILURE"
    assert event["username"] == "sahithya"
    assert event["attacker_ip"] == "192.168.56.1"
    assert event["source_port"] == 52345
    assert event["mitre_technique"] == "T1110.001"
    assert event["mitre_tactic"] == "Credential Access"
    assert event["severity"] == "HIGH"
    assert "Password Guessing" in event["intent"]


def test_scenario_2_invalid_user():
    line = "Invalid user nonexistentuser from 192.168.56.1 port 52346"
    event = parse_ssh_log_line(line)

    assert event is not None
    assert event["event_type"] == "SSH_INVALID_USER"
    assert event["username"] == "nonexistentuser"
    assert event["attacker_ip"] == "192.168.56.1"
    assert event["source_port"] == 52346
    assert event["mitre_technique"] == "T1110.001"
    assert event["severity"] == "HIGH"


def test_scenario_3_connection_reset():
    line = "Connection reset by invalid user ghost 192.168.56.1 port 52347 [preauth]"
    event = parse_ssh_log_line(line)

    assert event is not None
    assert event["event_type"] == "SSH_CONNECTION_RESET"
    assert event["username"] == "ghost"
    assert event["attacker_ip"] == "192.168.56.1"
    assert event["source_port"] == 52347
    assert event["mitre_technique"] == "T1110.001"


def test_scenario_4_multiple_usernames_enumeration():
    # 3 distinct usernames from same IP within the window triggers multiple_user_attack
    parse_ssh_log_line("Failed password for user1 from 192.168.56.1 port 50001 ssh2")
    parse_ssh_log_line("Failed password for user2 from 192.168.56.1 port 50002 ssh2")
    event3 = parse_ssh_log_line("Failed password for user3 from 192.168.56.1 port 50003 ssh2")

    assert event3 is not None
    assert event3["multiple_user_attack"] is True
    assert event3["unique_username_count"] == 3
    assert event3["severity"] in ["HIGH", "CRITICAL"]


def test_scenario_5_repeated_failures_brute_force():
    # 5 failures from same IP within window escalates to SSH_BRUTE_FORCE and CRITICAL
    ip = "192.168.56.200"
    for i in range(1, 5):
        ev = parse_ssh_log_line(f"Failed password for admin from {ip} port {50000 + i} ssh2")
        assert ev["event_type"] != "SSH_BRUTE_FORCE"

    ev5 = parse_ssh_log_line(f"Failed password for admin from {ip} port 50005 ssh2")
    assert ev5 is not None
    assert ev5["event_type"] == "SSH_BRUTE_FORCE"
    assert ev5["brute_force_detected"] is True
    assert ev5["severity"] == "CRITICAL"
    assert ev5["confidence"] >= 0.98


def test_scenario_6_successful_login():
    line = "Accepted publickey for sahithya from 192.168.56.1 port 54519 ssh2: ED25519 SHA256:LuZk..."
    event = parse_ssh_log_line(line)

    assert event is not None
    assert event["event_type"] == "SSH_AUTH_SUCCESS"
    assert event["username"] == "sahithya"
    assert event["attacker_ip"] == "192.168.56.1"
    assert event["mitre_technique"] == "T1078"
    assert event["mitre_tactic"] == "Defense Evasion"
    assert event["correlated_with_attack"] is False


def test_scenario_7_successful_login_after_failures():
    ip = "192.168.56.150"
    # Attack attempts first
    parse_ssh_log_line(f"Failed password for root from {ip} port 41001 ssh2")
    parse_ssh_log_line(f"Failed password for admin from {ip} port 41002 ssh2")

    # Now successful login from same attacker IP
    success_line = f"Accepted password for sahithya from {ip} port 41003 ssh2"
    success_event = parse_ssh_log_line(success_line)

    assert success_event is not None
    assert success_event["event_type"] == "SSH_AUTH_SUCCESS"
    assert success_event["correlated_with_attack"] is True
    assert success_event["previous_failure_count"] == 2
    assert success_event["previous_unique_username_count"] == 2
    assert success_event["severity"] == "HIGH"
    assert "Following Recent Authentication Attack" in success_event["intent"]


def test_scenario_8_preauth_disconnect():
    line = "Disconnected from invalid user admin 192.168.56.1 port 45683 [preauth]"
    event = parse_ssh_log_line(line)

    assert event is not None
    assert event["event_type"] == "SSH_PREAUTH_DISCONNECT"
    assert event["username"] == "admin"
    assert event["attacker_ip"] == "192.168.56.1"
    assert event["mitre_technique"] == "T1110.001"


def test_scenario_9_normal_disconnect():
    line = "Disconnected from 192.168.56.1 port 45684"
    event = parse_ssh_log_line(line)

    assert event is not None
    assert event["event_type"] == "SSH_DISCONNECT"
    assert event["attacker_ip"] == "192.168.56.1"
    assert event["source_port"] == 45684
    assert event["mitre_technique"] == "T1078"


def test_scenario_10_unrelated_pam_session_log():
    # Unrelated log line should return None and not crash
    line = "2026-09-24T10:40:11.183862+00:00 Ubuntu sshd-session[1821]: pam_unix(sshd:session): session opened for user sahithya"
    event = parse_ssh_log_line(line)

    assert event is None


def test_malformed_empty_lines():
    assert parse_ssh_log_line("") is None
    assert parse_ssh_log_line("   ") is None
    assert parse_ssh_log_line("random garbage systemd syslog message") is None


def test_technique_t1555_credential_store():
    line = "2026-09-25T05:24:07.448939+00:00 Ubuntu sudo: sahithya : PWD=/home/sahithya ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow"
    event = parse_ssh_log_line(line)
    assert event is not None
    assert event["mitre_technique"] == "T1555"
    assert event["mitre_tactic"] == "Credential Access"
    assert event["severity"] == "CRITICAL"
    assert event["event_type"] == "CREDENTIAL_STORE_ACCESS"


def test_technique_t1046_service_discovery():
    line = "2026-09-25T05:24:07.448939+00:00 Ubuntu sudo: sahithya : PWD=/home/sahithya ; USER=root ; COMMAND=/usr/bin/ss -tulpn"
    event = parse_ssh_log_line(line)
    assert event is not None
    assert event["mitre_technique"] == "T1046"
    assert event["mitre_tactic"] == "Discovery"
    assert event["severity"] == "MEDIUM"


def test_technique_t1059_004_unix_shell():
    line = "2026-09-25T05:24:07.448939+00:00 Ubuntu sudo: sahithya : PWD=/home/sahithya ; USER=root ; COMMAND=/bin/bash -c id"
    event = parse_ssh_log_line(line)
    assert event is not None
    assert event["mitre_technique"] == "T1059.004"
    assert event["mitre_tactic"] == "Execution"
    assert event["severity"] == "HIGH"


def test_technique_t1548_001_setuid_sudo():
    line = "2026-09-25T05:24:07.448939+00:00 Ubuntu sudo: sahithya : PWD=/home/sahithya ; USER=root ; COMMAND=/usr/bin/sudo -l"
    event = parse_ssh_log_line(line)
    assert event is not None
    assert event["mitre_technique"] == "T1548.001"
    assert event["mitre_tactic"] == "Privilege Escalation"
    assert event["severity"] == "HIGH"


def test_technique_t1190_exploit_public_facing_banner():
    line = "2026-09-25T05:25:16.199628+00:00 Ubuntu sshd-session[1909]: banner exchange: Connection from 192.168.56.1 port 51732: invalid format"
    event = parse_ssh_log_line(line)
    assert event is not None
    assert event["mitre_technique"] == "T1190"
    assert event["mitre_tactic"] == "Initial Access"
    assert event["severity"] == "CRITICAL"


def test_technique_t1071_001_web_protocols():
    line = "2026-09-25T05:24:07.448939+00:00 Ubuntu sudo: sahithya : PWD=/home/sahithya ; USER=root ; COMMAND=/usr/bin/curl -s http://127.0.0.1:8000/"
    event = parse_ssh_log_line(line)
    assert event is not None
    assert event["mitre_technique"] == "T1071.001"
    assert event["mitre_tactic"] == "Command and Control"
    assert event["severity"] == "MEDIUM"


def test_technique_t1082_system_info():
    line = "2026-09-25T05:24:07.448939+00:00 Ubuntu sudo: sahithya : PWD=/home/sahithya ; USER=root ; COMMAND=/usr/bin/uname -a"
    event = parse_ssh_log_line(line)
    assert event is not None
    assert event["mitre_technique"] == "T1082"
    assert event["mitre_tactic"] == "Discovery"
    assert event["severity"] == "LOW"


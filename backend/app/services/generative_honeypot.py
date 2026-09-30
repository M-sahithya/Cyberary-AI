"""
Generative AI Honeypot Core Service (shelLM Architecture)
Implements an LLM-powered interactive Linux shell emulator with:
- Per-session conversational state and command context (cwd, virtual filesystem, environment variables, command history)
- Support for local Ollama models (with automatic fallback to localhost/127.0.0.1)
- Deterministic, stateful fallback when LLM is offline or times out
- Realistic and safe Linux shell responses (Ubuntu 22.04 LTS persona)
- Safe execution guarantees (no real host commands executed, zero host egress)
"""

import asyncio
import json
import logging
import posixpath
import re
import shlex
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

import httpx

from app.config.settings import settings

logger = logging.getLogger("cyberary.generative_honeypot")


# ============================================================================
# BASELINE REALISTIC LINUX DECOY FILESYSTEM (Ubuntu 22.04 LTS)
# ============================================================================

DECOY_SYSTEM_FILES: Dict[str, str] = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "sync:x:4:65534:sync:/bin:/bin/sync\n"
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
        "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
        "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
        "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
        "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
        "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
        "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
        "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        "_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n"
        "systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
        "systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
        "messagebus:x:103:105::/nonexistent:/usr/sbin/nologin\n"
        "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin\n"
        "analyst:x:1000:1000:SOC Analyst,,,:/home/analyst:/bin/bash"
    ),
    "/etc/shadow": (
        "root:$6$rounds=656000$s9K8fJ2a$9vQ7W5p2J0Yc.v1EwTz7xL.f8Nm1Q3b4V5g6H7j8K9l0M1n2O3p4Q5r6S7t8U9v0W1x2Y3z:19738:0:99999:7:::\n"
        "daemon:*:19000:0:99999:7:::\n"
        "bin:*:19000:0:99999:7:::\n"
        "sys:*:19000:0:99999:7:::\n"
        "sync:*:19000:0:99999:7:::\n"
        "games:*:19000:0:99999:7:::\n"
        "man:*:19000:0:99999:7:::\n"
        "lp:*:19000:0:99999:7:::\n"
        "mail:*:19000:0:99999:7:::\n"
        "news:*:19000:0:99999:7:::\n"
        "uucp:*:19000:0:99999:7:::\n"
        "proxy:*:19000:0:99999:7:::\n"
        "www-data:*:19000:0:99999:7:::\n"
        "backup:*:19000:0:99999:7:::\n"
        "list:*:19000:0:99999:7:::\n"
        "irc:*:19000:0:99999:7:::\n"
        "nobody:*:19000:0:99999:7:::\n"
        "_apt:*:19000:0:99999:7:::\n"
        "systemd-network:*:19000:0:99999:7:::\n"
        "systemd-resolve:*:19000:0:99999:7:::\n"
        "messagebus:*:19000:0:99999:7:::\n"
        "sshd:*:19000:0:99999:7:::\n"
        "analyst:$6$rounds=656000$h8N2mK1p$0xL9jK3b4V5g6H7j8K9l0M1n2O3p4Q5r6S7t8U9v0W1x2Y3z4A5b6C7d8E9f0G1h2I:19738:0:99999:7:::"
    ),
    "/etc/os-release": (
        'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
        'NAME="Ubuntu"\n'
        'VERSION_ID="22.04"\n'
        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
        'VERSION_CODENAME=jammy\n'
        'ID=ubuntu\n'
        'ID_LIKE=debian\n'
        'HOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
        'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
        'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
        'UBUNTU_CODENAME=jammy'
    ),
    "/etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\n",
    "/etc/hostname": "lab-honeypot-01\n",
    "/etc/hosts": (
        "127.0.0.1\tlocalhost\n"
        "127.0.1.1\tlab-honeypot-01.cyberary.local\tlab-honeypot-01\n"
        "192.168.56.103\tubuntu-telemetry-vm\n"
        "10.0.1.1\tgateway.cyberary.local\n"
    ),
    "/etc/crontab": (
        "SHELL=/bin/sh\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
        "# m h dom mon dow user  command\n"
        "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
        "25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
        "47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
        "52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n"
        "*/10 *  * * *   root    /root/scripts/backup.sh >/dev/null 2>&1\n"
    ),
    "/proc/version": (
        "Linux version 5.15.0-89-generic (buildd@lcy02-amd64-077) "
        "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) #99-Ubuntu SMP Mon Oct 30 20:49:32 UTC 2023\n"
    ),
    "/proc/cpuinfo": (
        "processor\t: 0\n"
        "vendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\n"
        "model\t\t: 63\n"
        "model name\t: Intel(R) Core(TM) i7-10700K CPU @ 3.80GHz\n"
        "stepping\t: 2\n"
        "cpu MHz\t\t: 3792.000\n"
        "cache size\t: 16384 KB\n"
        "cpu cores\t: 4\n"
    ),
    "/proc/meminfo": (
        "MemTotal:        8142848 kB\n"
        "MemFree:         4391216 kB\n"
        "MemAvailable:    5981240 kB\n"
        "Buffers:          214580 kB\n"
        "Cached:          1894320 kB\n"
        "SwapTotal:       2097148 kB\n"
        "SwapFree:        2097148 kB\n"
    ),
    "/root/.bashrc": (
        "# ~/.bashrc: executed by bash(1) for non-login shells.\n"
        "export PS1='\\[\\e]0;\\u@\\h: \\w\\a\\]\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '\n"
        "alias ls='ls --color=auto'\n"
        "alias ll='ls -la'\n"
    ),
    "/root/.bash_history": (
        "ls -la\n"
        "apt update\n"
        "systemctl status sshd\n"
        "cat /root/config.yaml\n"
        "./scripts/backup.sh\n"
    ),
    "/root/config.yaml": (
        "database:\n"
        "  host: 127.0.0.1\n"
        "  port: 3306\n"
        "  user: lab_admin\n"
        "  pass: C0ntr0ll3d_L@b_P@ssw0rd!\n"
        "  database: cyberary_core\n"
        "api_keys:\n"
        "  internal_service: sec_token_98347104928347120\n"
    ),
    "/root/backup.tar.gz": "[BINARY ARCHIVE: 1024 bytes]",
    "/root/scripts/backup.sh": "#!/bin/bash\ntar -czf /root/backup.tar.gz /var/www /etc/nginx >/dev/null 2>&1\n",
}

# Base directories present in a standard Linux installation
BASE_DIRECTORY_ENTRIES: Dict[str, List[str]] = {
    "/": [
        "bin", "boot", "dev", "etc", "home", "lib", "lib64",
        "media", "mnt", "opt", "proc", "root", "run", "sbin",
        "srv", "sys", "tmp", "usr", "var"
    ],
    "/root": [
        ".bashrc", ".profile", ".bash_history",
        "backup.tar.gz", "config.yaml", "scripts", "ssh_keys"
    ],
    "/root/scripts": ["backup.sh"],
    "/root/ssh_keys": ["id_rsa.pub"],
    "/etc": [
        "passwd", "shadow", "hosts", "hostname", "os-release",
        "issue", "crontab", "ssh", "network", "ssl", "systemd"
    ],
    "/tmp": [],
    "/var": ["log", "run", "tmp", "www", "mail", "backups", "cache", "spool"],
    "/var/log": ["auth.log", "syslog", "dpkg.log", "journal", "nginx"],
    "/home": ["analyst"],
    "/home/analyst": [".bashrc", ".profile", ".bash_logout"],
}


# ============================================================================
# SESSION STATE CONTAINER
# ============================================================================

class HoneypotSessionState:
    """
    Maintains per-session contextual state:
    - Current working directory (cwd)
    - Virtual in-memory filesystem modifications (created/modified/deleted files)
    - Session environment variables
    - Command and response conversation history
    - Metadata and activity timestamps
    """

    def __init__(
        self,
        session_id: str,
        attacker_ip: str = "10.0.1.105",
        username: str = "root",
        hostname: str = "lab-honeypot-01",
        cwd: str = "/root",
    ):
        self.session_id: str = session_id
        self.attacker_ip: str = attacker_ip
        self.username: str = username
        self.hostname: str = hostname
        self.cwd: str = cwd
        self.previous_cwd: str = "/root"
        self.env: Dict[str, str] = {
            "USER": username,
            "LOGNAME": username,
            "HOME": "/root" if username == "root" else f"/home/{username}",
            "SHELL": "/bin/bash",
            "HOSTNAME": hostname,
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm-256color",
            "LANG": "en_US.UTF-8",
            "PWD": cwd,
        }
        # Virtual filesystem: maps normalized absolute paths -> string content
        self.virtual_files: Dict[str, str] = {}
        # Virtual directories: set of normalized absolute paths created by attacker
        self.virtual_dirs: set[str] = set()
        # Deleted baseline files (e.g. if attacker runs rm /root/config.yaml)
        self.deleted_paths: set[str] = set()
        # Chronological command history for context injection
        self.history: List[Dict[str, Any]] = []
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self.last_active: str = datetime.now(timezone.utc).isoformat()
        self.engine_used: str = "deterministic_fallback"
        # Advanced Intelligence State (shelLM Future Work)
        self.suspicion_score: float = 0.0
        self.suspicion_level: str = "LOW"
        self.human_vs_bot: Dict[str, Any] = {"classification": "INSUFFICIENT_DATA", "confidence": 0.5}
        self.planted_breadcrumbs: List[Dict[str, str]] = []
        self.semantic_summary: Dict[str, Any] = {}

    def normalize_path(self, target: str) -> str:
        """Resolves target against cwd and returns canonical POSIX path."""
        target = target.strip()
        if not target:
            return self.cwd

        # Handle ~ expansion
        home_dir = self.env.get("HOME", "/root")
        if target == "~" or target.startswith("~/"):
            target = home_dir + target[1:]

        if not target.startswith("/"):
            target = posixpath.join(self.cwd, target)

        normalized = posixpath.normpath(target)
        return normalized

    def file_exists(self, abs_path: str) -> bool:
        """Checks if a file exists in virtual fs or baseline system files."""
        if abs_path in self.deleted_paths:
            return False
        if abs_path in self.virtual_files:
            return True
        return abs_path in DECOY_SYSTEM_FILES

    def dir_exists(self, abs_path: str) -> bool:
        """Checks if a directory exists in baseline or virtual fs."""
        if abs_path in self.deleted_paths:
            return False
        if abs_path in self.virtual_dirs:
            return True
        if abs_path in BASE_DIRECTORY_ENTRIES:
            return True
        # Check if any virtual file resides in this directory
        prefix = abs_path.rstrip("/") + "/"
        for vf in self.virtual_files:
            if vf.startswith(prefix):
                return True
        return False

    def list_dir(self, abs_path: str) -> List[Tuple[str, bool]]:
        """
        Lists directory contents combining baseline and virtual entries.
        Returns list of (name, is_dir).
        """
        entries: Dict[str, bool] = {}

        # 1. Baseline entries
        if abs_path in BASE_DIRECTORY_ENTRIES:
            for item in BASE_DIRECTORY_ENTRIES[abs_path]:
                item_path = posixpath.join(abs_path, item)
                if item_path not in self.deleted_paths:
                    is_dir = (
                        item_path in BASE_DIRECTORY_ENTRIES
                        or item in ("bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt", "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr", "var", "scripts", "ssh_keys", "nginx")
                    )
                    entries[item] = is_dir

        # 2. Virtual directories
        prefix = abs_path.rstrip("/") + "/" if abs_path != "/" else "/"
        for vdir in self.virtual_dirs:
            if vdir.startswith(prefix) and vdir != abs_path:
                rel = vdir[len(prefix):].split("/")[0]
                if rel:
                    entries[rel] = True

        # 3. Virtual files
        for vf in self.virtual_files:
            if vf.startswith(prefix) and vf not in self.deleted_paths:
                rel = vf[len(prefix):].split("/")[0]
                if "/" in vf[len(prefix):]:
                    entries[rel] = True  # subdirectory component
                else:
                    entries[rel] = False

        return sorted([(k, v) for k, v in entries.items()])

    def get_file_content(self, abs_path: str) -> Optional[str]:
        """Retrieves content from virtual fs or baseline decoy files."""
        if abs_path in self.deleted_paths:
            return None
        if abs_path in self.virtual_files:
            return self.virtual_files[abs_path]
        return DECOY_SYSTEM_FILES.get(abs_path)

    def write_file(self, abs_path: str, content: str, append: bool = False) -> None:
        """Writes or appends content to virtual filesystem."""
        if abs_path in self.deleted_paths:
            self.deleted_paths.remove(abs_path)

        if append and abs_path in self.virtual_files:
            self.virtual_files[abs_path] += content
        elif append and abs_path in DECOY_SYSTEM_FILES:
            self.virtual_files[abs_path] = DECOY_SYSTEM_FILES[abs_path] + content
        else:
            self.virtual_files[abs_path] = content

        # Ensure parent directory is tracked
        parent = posixpath.dirname(abs_path)
        if parent:
            self.virtual_dirs.add(parent)

    def make_dir(self, abs_path: str) -> None:
        """Creates a virtual directory."""
        if abs_path in self.deleted_paths:
            self.deleted_paths.remove(abs_path)
        self.virtual_dirs.add(abs_path)

    def remove_path(self, abs_path: str) -> bool:
        """Removes a file or directory from virtual and baseline fs."""
        removed = False
        if abs_path in self.virtual_files:
            del self.virtual_files[abs_path]
            removed = True
        if abs_path in self.virtual_dirs:
            self.virtual_dirs.remove(abs_path)
            removed = True
        if abs_path in DECOY_SYSTEM_FILES or abs_path in BASE_DIRECTORY_ENTRIES:
            self.deleted_paths.add(abs_path)
            removed = True

        # Remove any child paths if directory
        prefix = abs_path.rstrip("/") + "/"
        to_del_files = [f for f in self.virtual_files if f.startswith(prefix)]
        for f in to_del_files:
            del self.virtual_files[f]
            removed = True

        return removed

    def change_dir(self, target: str) -> Tuple[bool, str]:
        """
        Attempts to change directory. Returns (success, error_message).
        Updates self.cwd and self.previous_cwd on success.
        """
        target = target.strip()
        if not target or target == "~":
            new_cwd = self.env.get("HOME", "/root")
        elif target == "-":
            new_cwd = self.previous_cwd
        else:
            new_cwd = self.normalize_path(target)

        if not self.dir_exists(new_cwd):
            return False, f"bash: cd: {target}: No such file or directory"

        self.previous_cwd = self.cwd
        self.cwd = new_cwd
        self.env["PWD"] = new_cwd
        return True, ""

    def add_history(self, command: str, response: str, engine: str = "fallback") -> None:
        """Appends a command exchange to the session context history."""
        self.history.append({
            "command": command,
            "response": response,
            "engine": engine,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        self.last_active = datetime.now(timezone.utc).isoformat()
        self.engine_used = engine
        if len(self.history) > 40:
            self.history = self.history[-40:]

    def to_dict(self) -> Dict[str, Any]:
        """Serializes session state to a JSON-compatible dictionary."""
        return {
            "session_id": self.session_id,
            "attacker_ip": self.attacker_ip,
            "username": self.username,
            "hostname": self.hostname,
            "cwd": self.cwd,
            "previous_cwd": self.previous_cwd,
            "env": self.env,
            "virtual_files": self.virtual_files,
            "virtual_dirs": list(self.virtual_dirs),
            "deleted_paths": list(self.deleted_paths),
            "created_at": self.created_at,
            "last_active": self.last_active,
            "engine_used": self.engine_used,
            "command_count": len(self.history),
            "suspicion_score": self.suspicion_score,
            "suspicion_level": self.suspicion_level,
            "human_vs_bot": self.human_vs_bot,
            "planted_breadcrumbs": self.planted_breadcrumbs,
            "semantic_summary": self.semantic_summary,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "HoneypotSessionState":
        """Reconstructs session state from dictionary."""
        inst = cls(
            session_id=data.get("session_id", "default"),
            attacker_ip=data.get("attacker_ip", "10.0.1.105"),
            username=data.get("username", "root"),
            hostname=data.get("hostname", "lab-honeypot-01"),
            cwd=data.get("cwd", "/root"),
        )
        inst.previous_cwd = data.get("previous_cwd", "/root")
        if "env" in data and isinstance(data["env"], dict):
            inst.env.update(data["env"])
        inst.virtual_files = data.get("virtual_files", {})
        inst.virtual_dirs = set(data.get("virtual_dirs", []))
        inst.deleted_paths = set(data.get("deleted_paths", []))
        inst.created_at = data.get("created_at", inst.created_at)
        inst.last_active = data.get("last_active", inst.last_active)
        inst.engine_used = data.get("engine_used", "deterministic_fallback")
        inst.suspicion_score = float(data.get("suspicion_score", 0.0))
        inst.suspicion_level = data.get("suspicion_level", "LOW")
        inst.human_vs_bot = data.get("human_vs_bot", {"classification": "INSUFFICIENT_DATA", "confidence": 0.5})
        inst.planted_breadcrumbs = data.get("planted_breadcrumbs", [])
        inst.semantic_summary = data.get("semantic_summary", {})
        return inst


# ============================================================================
# STATE MANAGER (THREAD-SAFE MEMORY CACHE)
# ============================================================================

class HoneypotStateManager:
    """In-memory cache for fast interactive shell sessions."""

    def __init__(self):
        self._sessions: Dict[str, HoneypotSessionState] = {}
        self._lock = asyncio.Lock()

    async def get_or_create(
        self,
        session_id: str,
        attacker_ip: str = "10.0.1.105",
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> HoneypotSessionState:
        """Retrieves active session state or initializes from DB metadata/defaults."""
        async with self._lock:
            if session_id in self._sessions:
                return self._sessions[session_id]

            if existing_metadata and isinstance(existing_metadata, dict):
                try:
                    state = HoneypotSessionState.from_dict(existing_metadata)
                    state.session_id = session_id
                    state.attacker_ip = attacker_ip
                    self._sessions[session_id] = state
                    return state
                except Exception as err:
                    logger.warning(f"Failed to restore session {session_id} from metadata: {err}")

            new_state = HoneypotSessionState(session_id=session_id, attacker_ip=attacker_ip)
            self._sessions[session_id] = new_state
            return new_state

    async def reset_session(self, session_id: str) -> HoneypotSessionState:
        """Resets a session back to initial root shell state."""
        async with self._lock:
            new_state = HoneypotSessionState(session_id=session_id)
            self._sessions[session_id] = new_state
            return new_state


# Singleton state manager instance
state_manager = HoneypotStateManager()


# ============================================================================
# DETERMINISTIC STATEFUL SHELL EMULATOR (Zero-Failure Fallback Engine)
# ============================================================================

def stateful_fallback_emulate(state: HoneypotSessionState, command: str) -> str:
    """
    Intelligent, stateful Linux shell emulator that maintains exact context
    (cwd, virtual filesystem, environment variables, command history)
    without requiring an external LLM.
    """
    cmd_raw = command.strip()
    if not cmd_raw:
        return ""

    # Check for redirection: cmd > file or cmd >> file
    redirect_match = re.search(r"^(.*?)\s*(>>|>)\s*([^\s]+)$", cmd_raw)
    if redirect_match:
        base_cmd = redirect_match.group(1).strip()
        op = redirect_match.group(2)
        target_file = redirect_match.group(3).strip()

        # Handle echo "text" > file
        if base_cmd.startswith("echo"):
            text_part = base_cmd[4:].strip()
            if (text_part.startswith('"') and text_part.endswith('"')) or (
                text_part.startswith("'") and text_part.endswith("'")
            ):
                content = text_part[1:-1]
            else:
                content = text_part

            # Variable substitution
            content = _substitute_env_vars(content, state.env)

            abs_target = state.normalize_path(target_file)
            state.write_file(abs_target, content + "\n", append=(op == ">>"))
            return ""

        # For other commands redirected to file: evaluate and save
        base_output = stateful_fallback_emulate(state, base_cmd)
        abs_target = state.normalize_path(target_file)
        state.write_file(abs_target, base_output + "\n", append=(op == ">>"))
        return ""

    # Handle command piping or chaining: simple separation for basic chains
    if " && " in cmd_raw:
        parts = cmd_raw.split(" && ", 1)
        out1 = stateful_fallback_emulate(state, parts[0])
        out2 = stateful_fallback_emulate(state, parts[1])
        return (out1 + "\n" + out2).strip()

    # Tokenize arguments safely
    try:
        tokens = shlex.split(cmd_raw)
    except ValueError:
        tokens = cmd_raw.split()

    if not tokens:
        return ""

    cmd_name = tokens[0]
    args = tokens[1:]

    # 1. Directory Navigation: cd
    if cmd_name == "cd":
        target = args[0] if args else "~"
        success, err = state.change_dir(target)
        if not success:
            return err
        return ""

    # 2. Print Working Directory: pwd
    if cmd_name == "pwd":
        return state.cwd

    # 3. Directory Listing: ls
    if cmd_name == "ls":
        return _emulate_ls(state, args)

    # 4. Create empty file: touch
    if cmd_name == "touch":
        if not args:
            return "touch: missing file operand\nTry 'touch --help' for more information."
        for arg in args:
            if not arg.startswith("-"):
                abs_p = state.normalize_path(arg)
                state.write_file(abs_p, "")
        return ""

    # 5. Make directory: mkdir
    if cmd_name == "mkdir":
        if not args:
            return "mkdir: missing operand\nTry 'mkdir --help' for more information."
        for arg in args:
            if not arg.startswith("-"):
                abs_p = state.normalize_path(arg)
                state.make_dir(abs_p)
        return ""

    # 6. Remove files: rm
    if cmd_name == "rm":
        if not args:
            return "rm: missing operand\nTry 'rm --help' for more information."
        for arg in args:
            if not arg.startswith("-"):
                abs_p = state.normalize_path(arg)
                state.remove_path(abs_p)
        return ""

    # 7. Print / Read Files: cat
    if cmd_name == "cat":
        if not args:
            return ""
        outputs = []
        for arg in args:
            if arg.startswith("-"):
                continue
            abs_p = state.normalize_path(arg)
            if state.dir_exists(abs_p) and not state.file_exists(abs_p):
                outputs.append(f"cat: {arg}: Is a directory")
                continue
            content = state.get_file_content(abs_p)
            if content is None:
                outputs.append(f"cat: {arg}: No such file or directory")
            else:
                outputs.append(content)
        return "\n".join(outputs)

    # 8. Head & Tail
    if cmd_name in ("head", "tail"):
        count = 10
        file_arg = None
        idx = 0
        while idx < len(args):
            if args[idx] in ("-n", "--lines") and idx + 1 < len(args):
                try:
                    count = int(args[idx + 1])
                except ValueError:
                    pass
                idx += 2
            elif args[idx].startswith("-n"):
                try:
                    count = int(args[idx][2:])
                except ValueError:
                    pass
                idx += 1
            else:
                file_arg = args[idx]
                idx += 1

        if not file_arg:
            return ""
        abs_p = state.normalize_path(file_arg)
        content = state.get_file_content(abs_p)
        if content is None:
            return f"{cmd_name}: cannot open '{file_arg}' for reading: No such file or directory"
        lines = content.splitlines()
        if cmd_name == "head":
            return "\n".join(lines[:count])
        else:
            return "\n".join(lines[-count:])

    # 9. Grep
    if cmd_name == "grep":
        if len(args) < 2:
            return "Usage: grep [OPTION]... PATTERNS [FILE]..."
        pattern = args[-2]
        target_file = args[-1]
        abs_p = state.normalize_path(target_file)
        content = state.get_file_content(abs_p)
        if content is None:
            return f"grep: {target_file}: No such file or directory"
        matches = [line for line in content.splitlines() if pattern in line]
        return "\n".join(matches)

    # 10. Echo
    if cmd_name == "echo":
        text = " ".join(args)
        if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
            text = text[1:-1]
        return _substitute_env_vars(text, state.env)

    # 11. Environment management: export, env, printenv
    if cmd_name == "export":
        if not args:
            return "\n".join(f'declare -x {k}="{v}"' for k, v in sorted(state.env.items()))
        for arg in args:
            if "=" in arg:
                k, v = arg.split("=", 1)
                state.env[k.strip()] = v.strip("'\"")
        return ""

    if cmd_name in ("env", "printenv"):
        return "\n".join(f"{k}={v}" for k, v in sorted(state.env.items()))

    # 12. Command History
    if cmd_name == "history":
        lines = []
        for i, h in enumerate(state.history, 1):
            lines.append(f"{i:5d}  {h['command']}")
        return "\n".join(lines) if lines else "    1  history"

    # 13. Identity and Host Profiling
    if cmd_name == "whoami":
        return state.username

    if cmd_name == "id":
        if state.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return f"uid=1000({state.username}) gid=1000({state.username}) groups=1000({state.username}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)"

    if cmd_name == "hostname":
        return state.hostname

    if cmd_name == "uname":
        if "-a" in args:
            return f"Linux {state.hostname} 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:49:32 UTC 2023 x86_64 GNU/Linux"
        if "-r" in args:
            return "5.15.0-89-generic"
        if "-m" in args:
            return "x86_64"
        return "Linux"

    if cmd_name == "date":
        return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")

    if cmd_name == "uptime":
        now_str = datetime.now(timezone.utc).strftime("%H:%M:%S")
        return f" {now_str} up 38 days,  4:12,  1 user,  load average: 0.08, 0.04, 0.01"

    if cmd_name == "clear":
        return "\033[2J\033[H"

    # 14. Privilege & Sudo Inspection
    if cmd_name == "sudo":
        if "-l" in args:
            return (
                f"Matching Defaults entries for {state.username} on {state.hostname}:\n"
                "    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin\n\n"
                f"User {state.username} may run the following commands on {state.hostname}:\n"
                "    (ALL : ALL) ALL"
            )
        if args and args[0] in ("-i", "-s", "su"):
            state.username = "root"
            state.env["USER"] = "root"
            state.env["HOME"] = "/root"
            return ""

    # 15. Process Inspection
    if cmd_name == "ps":
        return (
            "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
            "root           1  0.0  0.1 168344 11244 ?        Ss   08:00   0:02 /sbin/init\n"
            "root         412  0.0  0.0  72296  3420 ?        Ss   08:00   0:00 /usr/sbin/sshd -D\n"
            "root         520  0.0  0.1  88340  8912 ?        Ssl  08:01   0:01 /usr/sbin/rsyslogd -n\n"
            "root         601  0.0  0.0  24500  2890 ?        Ss   08:01   0:00 /usr/sbin/cron -f\n"
            f"{state.username}   1240  0.0  0.1  14280  4210 pts/0    Ss   09:15   0:00 -bash\n"
            f"{state.username}   1312  0.0  0.0  11420  3100 pts/0    R+   09:20   0:00 ps aux"
        )

    # 16. Network & Port Inspection
    if cmd_name in ("netstat", "ss"):
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
            "tcp6       0      0 :::22                   :::*                    LISTEN"
        )

    if cmd_name in ("ifconfig", "ip"):
        if cmd_name == "ip":
            return (
                "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000\n"
                "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                "    inet 127.0.0.1/8 scope host lo\n"
                "       valid_lft forever preferred_lft forever\n"
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000\n"
                "    link/ether 08:00:27:fa:41:88 brd ff:ff:ff:ff:ff:ff\n"
                f"    inet {state.attacker_ip[:7]}.105/24 brd {state.attacker_ip[:7]}.255 scope global eth0\n"
                "       valid_lft forever preferred_lft forever"
            )
        return (
            "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            f"        inet 10.0.1.105  netmask 255.255.255.0  broadcast 10.0.1.255\n"
            "        ether 08:00:27:fa:41:88  txqueuelen 1000  (Ethernet)\n"
            "        RX packets 241902  bytes 189284102 (189.2 MB)\n"
            "        TX packets 192810  bytes 142091844 (142.0 MB)\n\n"
            "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            "        inet 127.0.0.1  netmask 255.0.0.0\n"
            "        loop  txqueuelen 1000  (Local Loopback)"
        )

    # 17. Remote Egress & Downloads: curl / wget (Decoy trap)
    if cmd_name in ("curl", "wget"):
        url = args[-1] if args else "remote host"
        return (
            f"HTTP/1.1 200 OK\n"
            f"Connecting to {url}... [SIMULATED LAB EGRESS TRAPPED]\n"
            "Payload captured: 4096 bytes saved to honeypot audit sandbox."
        )

    # 18. File Permissions: chmod / chown
    if cmd_name in ("chmod", "chown"):
        return ""  # Silent success like standard unix

    # 19. Binary Location: which / whereis
    if cmd_name == "which":
        if not args:
            return ""
        bin_name = args[0]
        if bin_name in ("bash", "sh", "cat", "ls", "pwd", "rm", "mkdir", "touch", "chmod", "chown", "ps", "netstat", "ip", "ifconfig", "grep", "head", "tail"):
            return f"/usr/bin/{bin_name}"
        if bin_name in ("python", "python3"):
            return "/usr/bin/python3"
        return ""

    # 20. Script Execution Simulation
    if cmd_name in ("python", "python3", "perl", "bash", "sh") or cmd_name.startswith("./"):
        return "[Execution simulated in controlled honeypot sandbox environment]"

    # Fallback for unrecognized commands
    return f"bash: {cmd_name}: command not found"


def _emulate_ls(state: HoneypotSessionState, args: List[str]) -> str:
    """Helper to generate realistic Unix ls / ls -la output."""
    show_long = any(a in ("-l", "-la", "-al", "-lh", "-lah") or ("l" in a and a.startswith("-")) for a in args)
    show_all = any(a in ("-a", "-la", "-al", "-lah") or ("a" in a and a.startswith("-")) for a in args)

    target_dir = state.cwd
    for a in args:
        if not a.startswith("-"):
            target_dir = state.normalize_path(a)
            break

    if not state.dir_exists(target_dir):
        if state.file_exists(target_dir):
            return posixpath.basename(target_dir)
        return f"ls: cannot access '{target_dir}': No such file or directory"

    items = state.list_dir(target_dir)

    if not show_long:
        visible = [name for name, is_dir in items if show_all or not name.startswith(".")]
        return "  ".join(visible)

    # Detailed ls -la table
    lines = [f"total {max(len(items) * 4, 8)}"]
    if show_all:
        lines.append("drwxr-xr-x  4 root root 4096 Jan 15 10:00 .")
        lines.append("drwxr-xr-x 19 root root 4096 Jan 10 08:30 ..")

    for name, is_dir in items:
        if not show_all and name.startswith("."):
            continue
        perm = "drwxr-xr-x" if is_dir else "-rw-r--r--"
        size = 4096 if is_dir else 1024
        date_str = "Jan 15 10:02"
        lines.append(f"{perm}  1 root root {size:5d} {date_str} {name}")

    return "\n".join(lines)


def _substitute_env_vars(text: str, env: Dict[str, str]) -> str:
    """Substitutes $VAR and ${VAR} from session environment."""
    def _repl(match):
        v = match.group(1) or match.group(2)
        return env.get(v, "")
    return re.sub(r"\$(\w+)|\$\{(\w+)\}", _repl, text)


# ============================================================================
# LLM INTERACTION ENGINE (shelLM Architecture + Ollama Support)
# ============================================================================

from app.services.honeypot_intelligence import (
    advanced_history_manager,
    human_vs_bot_classifier,
    attacker_suspicion_analyzer,
    decoy_breadcrumb_engine,
)


class GenerativeHoneypotEngine:
    """
    LLM shell interaction engine based on the shelLM paper:
    - Builds persona and rich context prompt with semantic memory compaction
    - Queries local Ollama model if available
    - Performs safety post-processing (strips markdown, verifies no leaked internal host paths)
    - Syncs session state (updates cwd, virtual fs, env)
    - Integrates advanced intelligence: suspicion analyzer, human vs bot profiler, breadcrumbs
    - Gracefully falls back to stateful_fallback_emulate when Ollama is unavailable
    """

    def __init__(self):
        self.timeout = httpx.Timeout(connect=0.25, read=2.0, write=0.5, pool=0.5)
        self._last_ollama_failure: float = 0.0
        self._failure_backoff: float = 5.0

    def _build_shelLM_prompt(self, state: HoneypotSessionState, command: str) -> str:
        """Constructs high-fidelity system prompt with state context and compacted memory."""
        files_in_cwd = [name for name, _ in state.list_dir(state.cwd)]
        files_summary = ", ".join(files_in_cwd) if files_in_cwd else "(empty directory)"

        # Use Advanced History Manager (hierarchical semantic compaction to prevent context loss)
        history_context, semantic_summary = advanced_history_manager.compact_history(
            state.history,
            existing_summary=state.semantic_summary,
        )
        state.semantic_summary = semantic_summary

        prompt = f"""You are an interactive Linux shell in an Ubuntu 22.04 LTS honeypot environment.
Current system status:
- Operating System: Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)
- Hostname: {state.hostname}
- Logged-in User: {state.username}
- Current Working Directory (CWD): {state.cwd}
- Files in CWD: {files_summary}
- Attacker Source IP: {state.attacker_ip}

Session Command Context & History:
{history_context}

User Terminal Command:
$ {command}

STRICT INSTRUCTIONS:
1. Emulate the exact standard output (stdout) and standard error (stderr) that a real Ubuntu Linux bash shell returns for this command.
2. Return ONLY the raw terminal output.
3. Do NOT wrap output in markdown code blocks (never use ``` or ```bash).
4. Do NOT output any explanation, greetings, comments, or conversational text.
5. If a command succeeds silently in Linux (e.g. cd, touch, rm, export, mkdir), return absolutely nothing (empty string).
6. If the command does not exist, return: bash: <command>: command not found
7. Maintain consistency with the current working directory '{state.cwd}' and recent command history.
8. Never output real host internal credentials or code.
"""
        return prompt

    async def _query_ollama(self, prompt: str) -> Optional[str]:
        """
        Queries Ollama API at configured URL or fallback local endpoints.
        """
        import time
        now = time.time()
        if now - self._last_ollama_failure < self._failure_backoff:
            return None

        urls_to_try = []
        configured_url = settings.OLLAMA_BASE_URL.rstrip("/")

        if "ollama:" in configured_url:
            urls_to_try.append("http://127.0.0.1:11434")
        elif configured_url:
            urls_to_try.append(configured_url)
            urls_to_try.append("http://127.0.0.1:11434")
        else:
            urls_to_try.append("http://127.0.0.1:11434")

        # De-duplicate while preserving order
        candidate_urls = []
        for u in urls_to_try:
            if u not in candidate_urls:
                candidate_urls.append(u)

        for base_url in candidate_urls:
            try:
                async with httpx.AsyncClient(timeout=self.timeout) as client:
                    payload = {
                        "model": settings.LLM_MODEL,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": 0.2,
                            "top_p": 0.9,
                        },
                    }
                    res = await client.post(f"{base_url}/api/generate", json=payload)
                    if res.status_code == 200:
                        self._last_ollama_failure = 0.0
                        data = res.json()
                        raw_output = data.get("response", "")
                        return self._clean_llm_output(raw_output)
            except Exception as e:
                logger.debug(f"Ollama candidate {base_url} unreachable: {e}")
                continue

        self._last_ollama_failure = time.time()
        return None

    def _clean_llm_output(self, text: str) -> str:
        """Removes code fences, intro prefixes, and trims output."""
        if not text:
            return ""

        cleaned = text.strip()

        # Remove markdown codeblocks: ```bash\n...\n``` or ```\n...\n```
        if cleaned.startswith("```"):
            cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\n?", "", cleaned)
            cleaned = re.sub(r"\n?```$", "", cleaned)
            cleaned = cleaned.strip()

        # Strip accidental conversational prefixes
        cleaned = re.sub(r"^(stdout|output|terminal output):\s*", "", cleaned, flags=re.IGNORECASE)

        return cleaned

    def _sync_state_from_command(self, state: HoneypotSessionState, command: str) -> None:
        """
        Ensures internal session state (cwd, virtual files, environment)
        remains synchronized even when the LLM generates the response.
        """
        cmd_clean = command.strip()

        # Update cd
        if cmd_clean.startswith("cd ") or cmd_clean == "cd":
            parts = cmd_clean.split(maxsplit=1)
            target = parts[1] if len(parts) > 1 else "~"
            state.change_dir(target)

        # Update export
        elif cmd_clean.startswith("export "):
            arg = cmd_clean[7:].strip()
            if "=" in arg:
                k, v = arg.split("=", 1)
                state.env[k.strip()] = v.strip("'\"")

        # Update touch
        elif cmd_clean.startswith("touch "):
            parts = cmd_clean.split()[1:]
            for p in parts:
                if not p.startswith("-"):
                    state.write_file(state.normalize_path(p), "")

        # Update mkdir
        elif cmd_clean.startswith("mkdir "):
            parts = cmd_clean.split()[1:]
            for p in parts:
                if not p.startswith("-"):
                    state.make_dir(state.normalize_path(p))

        # Update rm
        elif cmd_clean.startswith("rm "):
            parts = cmd_clean.split()[1:]
            for p in parts:
                if not p.startswith("-"):
                    state.remove_path(state.normalize_path(p))

        # Update echo > or >>
        elif ">" in cmd_clean and "echo" in cmd_clean:
            match = re.search(r"^echo\s+(.*?)\s*(>>|>)\s*([^\s]+)$", cmd_clean)
            if match:
                text_part = match.group(1).strip()
                op = match.group(2)
                tgt = match.group(3).strip()
                if (text_part.startswith('"') and text_part.endswith('"')) or (
                    text_part.startswith("'") and text_part.endswith("'")
                ):
                    content = text_part[1:-1]
                else:
                    content = text_part
                abs_p = state.normalize_path(tgt)
                state.write_file(abs_p, content + "\n", append=(op == ">>"))

    async def execute_shell_command(
        self,
        session_id: str,
        command: str,
        attacker_ip: str = "10.0.1.105",
        existing_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Primary entry point for interactive honeypot shell commands:
        1. Retrieves or constructs session state.
        2. Attempts LLM generation via Ollama (if available).
        3. Falls back gracefully and deterministically if LLM is unavailable.
        4. Updates session state and history.
        5. Returns response, session metadata, cwd, and engine used.
        """
        state = await state_manager.get_or_create(
            session_id=session_id,
            attacker_ip=attacker_ip,
            existing_metadata=existing_metadata,
        )

        response_text: str = ""
        engine_used: str = "deterministic_fallback"

        # 1. Check if LLM provider is enabled
        if settings.LLM_PROVIDER.lower() in ("ollama", "local"):
            prompt = self._build_shelLM_prompt(state, command)
            llm_result = await self._query_ollama(prompt)
            if llm_result is not None:
                response_text = llm_result
                engine_used = f"ollama ({settings.LLM_MODEL})"
                # Synchronize local state with executed command
                self._sync_state_from_command(state, command)

        # 2. Fallback to stateful emulator if LLM produced no result
        if engine_used == "deterministic_fallback":
            response_text = stateful_fallback_emulate(state, command)

        # 3. Add to command history
        state.add_history(command=command, response=response_text, engine=engine_used)

        # 4. Attacker Suspicion Analysis (shelLM Section 7 Future Work)
        suspicion_res = attacker_suspicion_analyzer.analyze_suspicion(
            command=command,
            current_suspicion_score=state.suspicion_score,
            history=state.history,
        )
        state.suspicion_score = suspicion_res["suspicion_score"]
        state.suspicion_level = suspicion_res["level"]

        # 5. Human vs Bot Behavioral Classification (shelLM Section 7 Future Work)
        bot_res = human_vs_bot_classifier.analyze_behavior(state.history)
        state.human_vs_bot = bot_res

        # 6. Adaptive Decoy Breadcrumb Injection (shelLM Section 7 Future Work)
        # If attacker shows suspicion or explores credentials, plant breadcrumb
        if state.suspicion_score > 20.0 or any(k in command for k in ("passwd", "shadow", "env", "key", "token")):
            planted = decoy_breadcrumb_engine.plant_breadcrumbs_for_tactic("Credential Access", state.virtual_files)
            if planted:
                state.planted_breadcrumbs.extend(planted)
        elif any(k in command for k in ("sudo", "su ", "pkexec")):
            planted = decoy_breadcrumb_engine.plant_breadcrumbs_for_tactic("Privilege Escalation", state.virtual_files)
            if planted:
                state.planted_breadcrumbs.extend(planted)

        return {
            "session_id": state.session_id,
            "command": command,
            "response": response_text,
            "cwd": state.cwd,
            "username": state.username,
            "hostname": state.hostname,
            "engine_used": engine_used,
            "suspicion_score": state.suspicion_score,
            "suspicion_level": state.suspicion_level,
            "human_vs_bot": state.human_vs_bot,
            "planted_breadcrumbs": state.planted_breadcrumbs,
            "intelligence": {
                "suspicion_score": state.suspicion_score,
                "suspicion_level": state.suspicion_level,
                "human_vs_bot": state.human_vs_bot,
                "planted_breadcrumbs": state.planted_breadcrumbs,
            },
            "session_metadata": state.to_dict(),
        }


# Singleton engine instance
generative_honeypot_engine = GenerativeHoneypotEngine()

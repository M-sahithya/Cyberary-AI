"""
Honeypot Advanced Intelligence Engine (shelLM Future Work Implementation)
Implements research advancements proposed in Section 7 of the shelLM paper:
1. Advanced History Management & Semantic Memory Compaction (resolving 16k context wipe & "lost-in-the-middle")
2. Human vs. Bot Behavioral Classifier & Attack Profiler
3. Attacker Suspicion Scoring & Detection Evasion Analyzer
4. Adaptive Engagement & Dynamic Decoy Breadcrumb Engine
"""

import math
import re
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple, Set


# ============================================================================
# 1. ADVANCED HISTORY MANAGEMENT & SEMANTIC MEMORY COMPACTION
# ============================================================================

class AdvancedHoneypotHistoryManager:
    """
    Solves the context length limitation and behavior deterioration ('lost in the middle')
    identified in Section 7 of the shelLM paper:
    Instead of deleting history when context grows large, it hierarchically compacts older
    interactions into a structured semantic memory summary while maintaining a sliding window
    of recent verbatim exchanges.
    """

    def __init__(self, window_size: int = 8):
        self.window_size: int = window_size

    def compact_history(
        self,
        history: List[Dict[str, Any]],
        existing_summary: Optional[Dict[str, Any]] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Compacts full interaction history into:
        1. A high-signal concise text summary for prompt injection
        2. A structured metadata dictionary of extracted attacker knowledge
        """
        summary_data = existing_summary.copy() if existing_summary else {
            "files_investigated": [],
            "artifacts_created": [],
            "credentials_probed": [],
            "network_probed": [],
            "privileges_tested": False,
            "total_commands_compacted": 0,
        }

        if len(history) <= self.window_size:
            # All commands fit in active sliding window
            prompt_context = self._format_verbatim_window(history)
            return prompt_context, summary_data

        # Split into historical (to compact) and active window
        older_history = history[:-self.window_size]
        recent_window = history[-self.window_size:]

        # Extract semantic milestones from older commands
        for item in older_history:
            cmd = item.get("command", "").strip()
            if not cmd:
                continue

            # Track investigated files
            if cmd.startswith("cat ") or cmd.startswith("head ") or cmd.startswith("tail ") or cmd.startswith("more "):
                parts = cmd.split(maxsplit=1)
                if len(parts) > 1:
                    target = parts[1].strip()
                    if target not in summary_data["files_investigated"]:
                        summary_data["files_investigated"].append(target)

            # Track created files/artifacts
            if cmd.startswith("touch ") or ">" in cmd:
                parts = cmd.split()
                target = parts[-1]
                if target not in summary_data["artifacts_created"]:
                    summary_data["artifacts_created"].append(target)

            # Track credential probes
            if any(k in cmd for k in ("/etc/shadow", "/etc/passwd", "ssh", "key", "token", "auth")):
                if cmd not in summary_data["credentials_probed"]:
                    summary_data["credentials_probed"].append(cmd[:50])

            # Track network probes
            if any(k in cmd for k in ("netstat", "ip ", "ifconfig", "ss ", "curl", "wget", "ping")):
                if cmd not in summary_data["network_probed"]:
                    summary_data["network_probed"].append(cmd[:50])

            # Track privilege escalation attempts
            if "sudo" in cmd or "su " in cmd or "pkexec" in cmd:
                summary_data["privileges_tested"] = True

        summary_data["total_commands_compacted"] = len(older_history)

        # Build prompt context with semantic memory preamble + recent verbatim window
        compacted_lines = [
            f"[Compacted Earlier Session Context ({len(older_history)} commands)]",
        ]
        if summary_data["files_investigated"]:
            compacted_lines.append(f"- Previously Read: {', '.join(summary_data['files_investigated'][-5:])}")
        if summary_data["artifacts_created"]:
            compacted_lines.append(f"- Attacker Created: {', '.join(summary_data['artifacts_created'][-5:])}")
        if summary_data["credentials_probed"]:
            compacted_lines.append(f"- Probed Credentials: {', '.join(summary_data['credentials_probed'][-3:])}")
        if summary_data["privileges_tested"]:
            compacted_lines.append("- Tested Sudo/Root Privileges: Yes")
        compacted_lines.append("\n[Active Recent Commands]:")

        verbatim_recent = self._format_verbatim_window(recent_window)
        full_context = "\n".join(compacted_lines) + "\n" + verbatim_recent

        return full_context, summary_data

    def _format_verbatim_window(self, window: List[Dict[str, Any]]) -> str:
        lines = []
        for h in window:
            lines.append(f"$ {h.get('command', '')}")
            resp = h.get("response", "")
            if resp:
                resp_preview = resp if len(resp) < 200 else resp[:180] + "\n[... truncated]"
                lines.append(resp_preview)
        return "\n".join(lines)


# ============================================================================
# 2. HUMAN VS. BOT BEHAVIORAL CLASSIFIER & ATTACK PROFILER
# ============================================================================

class HumanVsBotClassifier:
    """
    Identifies whether an attacker inside the honeypot is a human operator or an automated script/bot.
    Features:
    - Command inter-arrival intervals and delay variance
    - Lexical diversity and exploratory vs automated command chains
    - Typo, backspace, and syntax error signatures
    - Automated scanner tool signatures (e.g. rapid bash loop execution, wordlist sprays)
    """

    def analyze_behavior(
        self,
        history: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        if not history:
            return {
                "classification": "INSUFFICIENT_DATA",
                "confidence": 0.5,
                "bot_score": 0.0,
                "human_score": 0.0,
                "indicators": ["Session initiated; awaiting command telemetry"],
            }

        indicators: List[str] = []
        bot_signals = 0.0
        human_signals = 0.0

        commands = [h.get("command", "").strip() for h in history if h.get("command")]
        n_cmds = len(commands)

        # 1. Automated chaining: &&, ||, ;, pipes in quick succession
        chained_cmds = sum(1 for c in commands if " && " in c or " | " in c or "; " in c)
        chain_ratio = chained_cmds / max(n_cmds, 1)
        if chain_ratio > 0.4:
            bot_signals += 2.5
            indicators.append(f"High automated command chaining density ({chain_ratio:.0%})")
        elif chain_ratio == 0 and n_cmds >= 3:
            human_signals += 1.0
            indicators.append("Interactive individual command cadence")

        # 2. Rapid scripted payload droppers (wget/curl piped to sh/bash)
        dropper_patterns = [
            r"curl.*\|.*bash",
            r"wget.*&&.*chmod",
            r"python.*-c.*socket",
            r"bash\s+-i\s+>&",
            r"cat\s+<<\s*EOF",
        ]
        has_dropper = any(any(re.search(p, c) for p in dropper_patterns) for c in commands)
        if has_dropper:
            bot_signals += 3.0
            indicators.append("Automated remote payload dropper signature detected")

        # 3. Exploratory interactive commands (typos, relative paths, nano/vim, manual ls)
        interactive_cmds = {"ls", "pwd", "cd", "cat", "whoami", "id", "uname -a", "history", "clear", "w", "w"}
        interactive_count = sum(1 for c in commands if any(c.startswith(k) for k in interactive_cmds))
        interactive_ratio = interactive_count / max(n_cmds, 1)

        if interactive_ratio > 0.6 and n_cmds >= 4:
            human_signals += 2.0
            indicators.append(f"High interactive shell exploration ratio ({interactive_ratio:.0%})")

        # 4. Command diversity / repetition
        unique_cmds = len(set(commands))
        diversity_ratio = unique_cmds / max(n_cmds, 1)
        if n_cmds >= 5 and diversity_ratio < 0.4:
            bot_signals += 2.0
            indicators.append("Low command diversity (automated loop or scanner repetition)")
        elif n_cmds >= 5 and diversity_ratio > 0.7:
            human_signals += 1.5
            indicators.append("High semantic command diversity typical of human reconnaissance")

        # 5. Inter-command timing analysis (if timestamps available)
        intervals = []
        for i in range(1, len(history)):
            t1_str = history[i - 1].get("timestamp")
            t2_str = history[i].get("timestamp")
            if t1_str and t2_str:
                try:
                    t1 = datetime.fromisoformat(t1_str)
                    t2 = datetime.fromisoformat(t2_str)
                    delta = abs((t2 - t1).total_seconds())
                    intervals.append(delta)
                except Exception:
                    pass

        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval < 0.5:
                bot_signals += 3.5
                indicators.append(f"Sub-second command cadence (avg {avg_interval:.2f}s) indicates automated script")
            elif 2.0 <= avg_interval <= 60.0:
                human_signals += 2.5
                indicators.append(f"Realistic human typing/thinking intervals (avg {avg_interval:.1f}s)")
            elif avg_interval > 120.0:
                human_signals += 1.0
                indicators.append("Extended idle intervals consistent with manual attacker inspection")

        # Compute normalized probabilities
        total_weight = bot_signals + human_signals
        if total_weight == 0:
            classification = "HYBRID_SCRIPTED"
            confidence = 0.6
            bot_prob = 0.5
            human_prob = 0.5
        else:
            bot_prob = round(bot_signals / total_weight, 2)
            human_prob = round(human_signals / total_weight, 2)

            if bot_prob >= 0.65:
                classification = "AUTOMATED_BOT"
                confidence = bot_prob
            elif human_prob >= 0.65:
                classification = "HUMAN_ATTACKER"
                confidence = human_prob
            else:
                classification = "HYBRID_SCRIPTED"
                confidence = max(bot_prob, human_prob)

        return {
            "classification": classification,
            "confidence": confidence,
            "bot_score": bot_prob,
            "human_score": human_prob,
            "indicators": indicators,
            "total_commands_analyzed": n_cmds,
        }


# ============================================================================
# 3. ATTACKER SUSPICION SCORING & DETECTION EVASION ANALYZER
# ============================================================================

class AttackerSuspicionAnalyzer:
    """
    Monitors whether an attacker suspects or is actively fingerprinting the honeypot.
    Detects honeypot identification techniques:
    - Virtualization / hypervisor artifact probing (dmidecode, lspci, systemd-detect-virt)
    - Honeypot software signature probing (cowrie, kippo, dionaea)
    - Kernel module & procfs discrepancies (/proc/version vs uname, /proc/modules)
    - Network interface anomaly probes (checking for default sandbox MAC addresses)
    """

    SUSPICION_SIGNATURES: List[Dict[str, Any]] = [
        {
            "pattern": r"(systemd-detect-virt|dmidecode|lspci|lshw|virt-what|qemu|kvm|vmware|vbox|xen)",
            "weight": 28.0,
            "reason": "Virtualization and hypervisor environment fingerprinting probe",
        },
        {
            "pattern": r"(cowrie|kippo|dionaea|honeyd|glastopf)",
            "weight": 40.0,
            "reason": "Direct honeypot software signature search in filesystem/processes",
        },
        {
            "pattern": r"cat\s+/proc/(modules|net/tcp|kallsyms|sys/kernel)",
            "weight": 22.0,
            "reason": "Deep kernel module & procfs honeypot emulation consistency verification",
        },
        {
            "pattern": r"(ip\s+link|ifconfig).*08:00:27",
            "weight": 18.0,
            "reason": "VirtualBox MAC address OUI inspection",
        },
        {
            "pattern": r"(strace|gdb|ptrace|objdump)",
            "weight": 15.0,
            "reason": "Binary debugging and syscall interception inspection",
        },
        {
            "pattern": r"(check_honeypot|honey_trap|fake_root|is_sandbox)",
            "weight": 35.0,
            "reason": "Attacker running automated honeypot detection utility",
        },
    ]

    def analyze_suspicion(
        self,
        command: str,
        current_suspicion_score: float = 0.0,
        history: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        added_score = 0.0
        reasons: List[str] = []
        cmd_clean = command.strip().lower()

        for sig in self.SUSPICION_SIGNATURES:
            if re.search(sig["pattern"], cmd_clean):
                added_score += sig["weight"]
                reasons.append(sig["reason"])

        # Natural slow decay if normal Linux commands are executed
        decay = 1.5 if not reasons else 0.0
        new_score = max(0.0, min(100.0, current_suspicion_score + added_score - decay))

        if new_score >= 65.0:
            level = "CRITICAL_DETECTION_RISK"
            deception_recommendation = "Deploy high-fidelity kernel decoy responses and plant plausible administrative error logs."
        elif new_score >= 35.0:
            level = "ELEVATED"
            deception_recommendation = "Maintain consistent directory state and offer enticing decoy configuration breadcrumbs."
        else:
            level = "LOW"
            deception_recommendation = "Normal decoy emulation; attacker appears unsuspicious."

        return {
            "suspicion_score": round(new_score, 1),
            "level": level,
            "signals_detected": reasons,
            "deception_recommendation": deception_recommendation,
        }


# ============================================================================
# 4. ADAPTIVE ENGAGEMENT & DYNAMIC DECOY BREADCRUMB ENGINE
# ============================================================================

class DecoyBreadcrumbEngine:
    """
    Dynamically plants enticing deceptive artifacts into the virtual filesystem
    based on the attacker's observed objectives to maximize dwell time and engagement.
    """

    BREADCRUMB_CATALOG: List[Dict[str, Any]] = [
        {
            "trigger_tactic": "Credential Access",
            "path": "/root/.aws/credentials",
            "content": (
                "[default]\n"
                "aws_access_key_id = AKIA_CYBERARY_CANARY_LAB_2026\n"
                "aws_secret_access_key = 9Fk3mQ7xL2wP0vN8jH4bC1dG6sT5aZ8y\n"
                "region = us-east-1\n"
            ),
            "description": "Canary AWS Cloud API Access Credentials",
        },
        {
            "trigger_tactic": "Discovery",
            "path": "/var/backups/cyberary_db_export.sql",
            "content": (
                "-- Cyberary Core Database Schema Dump (Canary)\n"
                "CREATE TABLE admin_users (\n"
                "    id INT PRIMARY KEY,\n"
                "    username VARCHAR(50),\n"
                "    password_hash VARCHAR(120)\n"
                ");\n"
                "INSERT INTO admin_users VALUES (1, 'soc_admin', '$2b$12$e8Y7zK1...CanaryDecoyHash');\n"
            ),
            "description": "Decoy SQL Database Export with Canary Admin Table",
        },
        {
            "trigger_tactic": "Privilege Escalation",
            "path": "/etc/cron.d/sync_backup",
            "content": (
                "# Scheduled system synchronization (Canary)\n"
                "* * * * * root /root/scripts/backup.sh >/dev/null 2>&1\n"
            ),
            "description": "Tempting root crontab job for local escalation attempts",
        },
    ]

    def plant_breadcrumbs_for_tactic(
        self,
        tactic: str,
        virtual_files: Dict[str, str],
    ) -> List[Dict[str, str]]:
        """Plants relevant breadcrumbs if not already present."""
        planted = []
        for bc in self.BREADCRUMB_CATALOG:
            if bc["trigger_tactic"].lower() == tactic.lower():
                path = bc["path"]
                if path not in virtual_files:
                    virtual_files[path] = bc["content"]
                    planted.append({
                        "path": path,
                        "description": bc["description"],
                        "tactic": bc["trigger_tactic"],
                    })
        return planted


# Singleton instances
advanced_history_manager = AdvancedHoneypotHistoryManager()
human_vs_bot_classifier = HumanVsBotClassifier()
attacker_suspicion_analyzer = AttackerSuspicionAnalyzer()
decoy_breadcrumb_engine = DecoyBreadcrumbEngine()

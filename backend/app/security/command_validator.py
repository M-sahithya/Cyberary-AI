"""
Command Validator (Stub — Phase 6)
Validates AI-generated shell commands before execution.
Commands must NEVER execute automatically.
"""

from typing import Tuple

# Dangerous commands that should always be blocked
BLOCKED_COMMANDS = [
    "rm -rf /",
    "mkfs",
    "dd if=/dev/zero",
    ":(){:|:&};:",
    "chmod -R 777 /",
    "shutdown",
    "reboot",
    "init 0",
    "init 6",
    "format",
    "fdisk",
]

# Dangerous patterns (regex will be added in Phase 6)
BLOCKED_PATTERNS = [
    "rm -rf",
    "wget.*|.*sh",
    "curl.*|.*bash",
    "> /dev/sd",
    "mv /* /dev/null",
]


def validate_command(command: str) -> Tuple[bool, str]:
    """
    Validate a command before it can be displayed for human review.

    Returns:
        Tuple of (is_safe, reason)
    """
    if not command or not command.strip():
        return False, "Empty command."

    command_lower = command.lower().strip()

    # Check blocked commands
    for blocked in BLOCKED_COMMANDS:
        if blocked in command_lower:
            return False, f"Blocked dangerous command pattern: {blocked}"

    # Check blocked patterns
    for pattern in BLOCKED_PATTERNS:
        if pattern in command_lower:
            return False, f"Blocked dangerous pattern: {pattern}"

    return True, "Command passed initial validation. Requires human approval."


def format_command_for_review(command: str, context: dict = None) -> dict:
    """
    Format a command for human review display.
    This is called before ANY command can be executed.
    """
    is_safe, reason = validate_command(command)

    return {
        "command": command,
        "is_safe": is_safe,
        "validation_message": reason,
        "requires_approval": True,  # ALWAYS true
        "context": context or {},
        "warning": "⚠️ This command will NOT execute until explicitly approved by a human operator.",
    }

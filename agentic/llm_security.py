"""
LLM Security Layer — command sanitization, prompt injection hardening,
and secret redaction for RedAmon.

Three protection layers:
    1. CommandSanitizer — blocks dangerous shell commands (rm -rf, dd, mkfs, etc.)
    2. PromptInjectorGuard — sanitizes user-supplied data to prevent injection
    3. SecretRedactor — strips API keys, tokens, passwords from LLM output
       before it's logged or stored

Usage:
    from agentic.llm_security import (
        CommandSanitizer, sanitize_target_data, redact_secrets
    )

    # Sanitize a command before execution.
    safe_cmd, blocked = CommandSanitizer.sanitize("rm -rf /tmp/data")
    if blocked:
        raise ValueError("Dangerous command: ...")

    # Sanitize target data for prompt injection.
    safe_target = sanitize_target_data("evil.com; DROP TABLE users")

    # Redact secrets from LLM output before logging.
    clean_output = redact_secrets(llm_response_text)
"""

import logging
import re as _re
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maximum length for sanitized strings (prevent injection via giant payloads).
MAX_SANITIZED_LENGTH = 5000


# ---------------------------------------------------------------------------
# 1. Command Sanitizer
# ---------------------------------------------------------------------------

@dataclass
class CommandSanitizeResult:
    """Result of command sanitization."""

    allowed: bool
    sanitized_command: str = ""
    blocked_patterns: list[str] = field(default_factory=list)
    risk_level: str = "safe"  # safe, caution, blocked

    def __bool__(self) -> bool:
        return self.allowed


class CommandSanitizer:
    """Blocks dangerous shell commands before execution.

    Uses a blocklist approach — any command containing a blocked pattern
    is rejected outright. Patterns are regex-based to catch variants.

    NOT intended as a comprehensive sandbox — use SandboxExecutor for
    actual code execution. This is a defense-in-depth layer for commands
    the LLM generates that might be run on the orchestrator host.
    """

    # Blocked patterns: regex → human description
    BLOCKED_PATTERNS = [
        # Destructive file operations.
        (r"\brm\s+(?:-rf?\s+|--recursive\s+)*/", "rm -rf / (recursive root)"),
        (r"\brm\s+(?:-rf?\s+|--recursive\s+)*\*", "rm with wildcard"),
        (r"\bdd\s+if=", "dd (raw disk write)"),
        (r"\bmkfs\b", "mkfs (format filesystem)"),
        (r"\bmke2fs\b", "mke2fs (format ext filesystem)"),
        (r"\bmkswap\b", "mkswap (format swap)"),

        # System disruption.
        (r"\bshutdown\b", "shutdown (halt system)"),
        (r"\breboot\b", "reboot (restart system)"),
        (r"\bpoweroff\b", "poweroff"),
        (r"\bhalt\b", "halt"),
        (r"\binit\s+[06]\b", "init 0/6 (shutdown/reboot)"),
        (r"\bsystemctl\s+(?:stop|disable|mask)\b", "systemctl stop/disable/mask"),

        # Privilege escalation (outside sandbox).
        (r"\bchmod\s+.*777", "chmod 777 (world-writable)"),
        (r"\bchmod\s+.*[su]\+s\b", "chmod +s (setuid/setgid)"),
        (r"\bchown\s+root:", "chown to root"),
        (r"\bsudo\s", "sudo invocation"),
        (r"\bsu\s+-", "su - (switch user)"),

        # Network disruption.
        (
            r"\biptables\s+-(?:F|X|P)\b",
            "iptables flush/delete (firewall removal)"
        ),
        (
            r"\bnft\s+flush\b",
            "nftables flush (firewall removal)"
        ),

        # Kernel manipulation.
        (r"\bmodprobe\b", "modprobe (kernel module load)"),
        (r"\binsmod\b", "insmod (kernel module insert)"),
        (r"\brmmod\b", "rmmod (kernel module remove)"),
        (r"\bsysctl\s+-w\b", "sysctl -w (kernel parameter write)"),

        # Egress/ingress safety (block outbound connections to random hosts).
        # We check for curl/wget/nc to non-scope targets — the policy_guard
        # handles this at iptables level, but we double-check here.
        (r"\bnc\s+[^l]", "netcat (nc) — potential reverse shell"),
        (r"\bbash\s+-i\s+>&\s+/dev/tcp", "bash reverse shell"),
        (r"\bpython3?\s+-c\s+.*socket", "Python reverse shell"),

        # Excessive recursion / fork bombs.
        (r":\(\s*\)\s*\{\s*:\|:&\s*\}\s*;", "fork bomb (:(){ :|:& };:)"),
        (r"\bperl\s+-e\s+.*fork", "Perl fork bomb"),
    ]

    # Patterns that require a WARNING but aren't fully blocked.
    CAUTION_PATTERNS = [
        (r"\bkill\s+-9\b", "kill -9 (force kill)"),
        (r"\bpkill\b", "pkill (kill by name)"),
        (r"\bkillall\b", "killall (kill all instances)"),
        (r"\bdocker\s+rm\b", "docker rm (container removal)"),
        (r"\bdocker\s+stop\b", "docker stop"),
        (r"\bgpasswd\b", "gpasswd (group password change)"),
        (r"\bpasswd\b", "passwd (password change)"),
    ]

    @classmethod
    def sanitize(cls, command: str) -> CommandSanitizeResult:
        """Check a command against blocked and caution patterns.

        Returns a CommandSanitizeResult. If ``allowed`` is False, the command
        MUST NOT be executed. If ``risk_level`` is ``"caution"``, the command
        should be reviewed by a human before execution.
        """
        blocked: list[str] = []
        cautions: list[str] = []

        # Truncate extremely long commands.
        if len(command) > MAX_SANITIZED_LENGTH:
            command = command[:MAX_SANITIZED_LENGTH] + " [TRUNCATED]"
            blocked.append("Command exceeds max length")

        # Check blocked patterns.
        for pattern, description in cls.BLOCKED_PATTERNS:
            if _re.search(pattern, command):
                blocked.append(description)

        if blocked:
            return CommandSanitizeResult(
                allowed=False,
                sanitized_command=command,
                blocked_patterns=blocked,
                risk_level="blocked",
            )

        # Check caution patterns.
        for pattern, description in cls.CAUTION_PATTERNS:
            if _re.search(pattern, command):
                cautions.append(description)

        if cautions:
            return CommandSanitizeResult(
                allowed=True,
                sanitized_command=command,
                blocked_patterns=cautions,
                risk_level="caution",
            )

        return CommandSanitizeResult(
            allowed=True,
            sanitized_command=command,
            risk_level="safe",
        )


# ---------------------------------------------------------------------------
# 2. Prompt Injection Hardening
# ---------------------------------------------------------------------------

# Control characters to strip from user-supplied data.
_CONTROL_CHARS = _re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")

# Characters that could be used for injection in prompts.
_INJECTION_MARKERS = [
    # Attempts to close the data block and inject new instructions.
    (r"```\s*system\b", "[CODE_BLOCK]"),
    (r"```\s*prompt\b", "[CODE_BLOCK]"),
    # System message injection.
    (r"<\s*\|?\s*SYSTEM\s*\|?\s*>", "[SYSTEM_TAG]"),
    (r"<\s*\|?\s*INSTRUCTION\s*\|?\s*>", "[INSTRUCTION_TAG]"),
    # Ignore-previous-instructions attacks.
    (
        r"(?:ignore|disregard|forget)\s+(?:all\s+)?(?:previous|above|prior)\s+"
        r"(?:instructions?|prompts?|messages?)",
        "[INSTRUCTION_OVERRIDE_ATTEMPT]",
    ),
    # Role-play override.
    (r"you\s+are\s+now\s+(?:a\s+)?(?:DAN|jailbreak)", "[ROLE_OVERRIDE_ATTEMPT]"),
]


def sanitize_target_data(data: str) -> str:
    """Sanitize user-supplied target data for LLM prompt inclusion.

    This is NOT a general sanitizer — it's designed specifically for data
    that will be embedded in LLM prompts. It:
        1. Strips control characters.
        2. Escapes backticks and triple-backticks (prevents markdown injection).
        3. Truncates to MAX_SANITIZED_LENGTH.
        4. Returns the sanitized string.

    Args:
        data: Raw user-supplied target data (domain, IP, URL, etc.).

    Returns:
        Sanitized string safe for prompt embedding.

    Example:
        >>> sanitize_target_data("evil.com; DROP TABLE users")
        'evil.com; DROP TABLE users'  # Special chars are preserved but
                                      # injection markers are neutralized
    """
    if not data:
        return ""

    # 1. Strip control characters.
    data = _CONTROL_CHARS.sub("", data)

    # 2. Truncate.
    if len(data) > MAX_SANITIZED_LENGTH:
        data = data[:MAX_SANITIZED_LENGTH]

    # 3. Neutralize injection markers — replace with safe placeholders.
    for pattern, replacement in _INJECTION_MARKERS:
        data = _re.sub(pattern, replacement, data, flags=_re.IGNORECASE)

    return data


def _wrap_target_in_data_block(target: str) -> str:
    """Wrap sanitized target data in a markdown data block.

    The data block is separated from the prompt template by a clear
    boundary, making prompt injection harder.
    """
    return f"```data\n{target}\n```"


# ---------------------------------------------------------------------------
# 3. Secret Redaction
# ---------------------------------------------------------------------------

# Patterns for common secret formats — matched and REDACTED from LLM output
# before logging or storage.
_SECRET_PATTERNS: list[tuple[str, str]] = [
    # OpenAI API keys.
    (r"sk-[A-Za-z0-9]{32,}", "[REDACTED: OpenAI API key]"),
    # Anthropic API keys.
    (r"sk-ant-[A-Za-z0-9_-]{32,}", "[REDACTED: Anthropic API key]"),
    # AWS access keys.
    (r"AKIA[0-9A-Z]{16}", "[REDACTED: AWS access key]"),
    # AWS secret keys (with surrounding context).
    (r"aws_secret_access_key[=:]\s*[\"']?([A-Za-z0-9/+]{40})", "[REDACTED: AWS secret key]"),
    # GitHub tokens.
    (r"gh[pousr]_[A-Za-z0-9_]{36,}", "[REDACTED: GitHub token]"),
    (r"github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+@[A-Za-z0-9]{40}", "[REDACTED: GitHub token URL]"),
    # Generic API key patterns.
    (r"api_?key[=:]\s*[\"']?([A-Za-z0-9_-]{20,64})", "[REDACTED: API key]"),
    (r"api_?secret[=:]\s*[\"']?([A-Za-z0-9_-]{20,64})", "[REDACTED: API secret]"),
    # JWT tokens.
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "[REDACTED: JWT token]"),
    # Generic bearer tokens.
    (r"bearer\s+([A-Za-z0-9_\-=]{20,})", "[REDACTED: Bearer token]"),
    # Private keys (SSH, GPG).
    (r"-----BEGIN (?:RSA|DSA|EC|OPENSSH|PGP) PRIVATE KEY-----", "[REDACTED: Private key]"),
    # Passwords in common formats.
    (r"(?i)password[=:]\s*\S{4,}", "[REDACTED: Password]"),
    (r"(?i)passwd[=:]\s*\S{4,}", "[REDACTED: Password]"),
    # Slack tokens.
    (r"xox[baprs]-[A-Za-z0-9-]+", "[REDACTED: Slack token]"),
    # Generic tokens.
    (r"(?i)token[=:]\s*\S{16,}", "[REDACTED: Token]"),
]


def redact_secrets(text: str) -> str:
    """Redact API keys, tokens, and credentials from text.

    Call this on LLM output BEFORE logging, storing, or rendering.
    This is defense-in-depth — the context_manager and report_agent
    should also call this.
    """
    if not text:
        return text

    original = text
    for pattern, replacement in _SECRET_PATTERNS:
        text = _re.sub(pattern, replacement, text)

    if text != original:
        logger.info(
            "Redacted secrets from output (%d → %d chars)",
            len(original), len(text),
        )

    return text


# ---------------------------------------------------------------------------
# Combined sanitization for target data going into LLM prompts
# ---------------------------------------------------------------------------

def secure_target_for_prompt(target: str) -> str:
    """Full sanitization pipeline for target data entering an LLM prompt.

    1. Sanitize control chars and injection markers.
    2. Wrap in a data block for clear separation from instructions.
    """
    safe = sanitize_target_data(target)
    return _wrap_target_in_data_block(safe)

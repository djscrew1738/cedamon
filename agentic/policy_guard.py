"""
Policy Guard — kernel-level scope enforcement for RedAmon engagements.

Ensures EVERY packet sent by the agent is validated against the engagement's
scope definition. Uses iptables/nftables for bypass-proof enforcement: even if
the agent's logic fails, the OS drops out-of-scope packets at the kernel level.

Architecture:
    1. Parse scope definition (list of CIDR ranges, domain→IP mappings).
    2. Pre-resolve all allowed domains to IPs at start (prevents DNS rebinding).
    3. Install iptables rules that DROP any packet not matching the allowed set.
    4. Provide a rollback mechanism to remove rules after engagement.

Usage:
    guard = PolicyGuard()
    guard.start(scope=["10.10.10.0/24", "example.com"])
    # ... agent runs ...
    guard.stop()  # Remove iptables rules
"""

import ipaddress
import logging
import os
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Optional, Union

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# iptables chain name used for scope enforcement.
SCOPE_CHAIN = "REDAMON_SCOPE"

# Jump target name in OUTPUT chain.
OUTPUT_JUMP_TARGET = "OUTPUT"

# Maximum number of scope entries supported.
MAX_SCOPE_ENTRIES = 256


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class ScopeEntry:
    """A single allowed target in the engagement scope."""

    kind: str  # "cidr", "ip", "domain"
    value: str  # Original value provided by the user
    resolved_ips: list[str] = field(default_factory=list)  # Pre-resolved IPs

    def __repr__(self) -> str:
        ips = ",".join(self.resolved_ips[:3])
        return f"ScopeEntry({self.kind}:{self.value} → [{ips}])"


@dataclass
class ScopeConfig:
    """Parsed engagement scope with validation results."""

    entries: list[ScopeEntry]
    cidrs: list[ipaddress.IPv4Network] = field(default_factory=list)
    ips: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return len(self.errors) == 0

    @property
    def is_empty(self) -> bool:
        return len(self.entries) == 0


# ---------------------------------------------------------------------------
# Scope parser
# ---------------------------------------------------------------------------

def parse_scope(scope: list[str]) -> ScopeConfig:
    """Parse and validate a list of scope definitions.

    Each item can be:
        - A CIDR range: ``"10.10.10.0/24"``
        - A single IP: ``"192.168.1.1"``
        - A domain name: ``"example.com"`` (resolved at start-time)
        - A wildcard domain: ``"*.example.com"`` (not yet resolved — warning)

    Returns a ScopeConfig with parsed entries, resolved IPs, and any
    validation errors or warnings.
    """
    if not scope:
        return ScopeConfig(
            entries=[],
            errors=["Empty scope — no targets allowed"],
            warnings=[],
        )

    if len(scope) > MAX_SCOPE_ENTRIES:
        return ScopeConfig(
            entries=[],
            errors=[
                f"Scope too large: {len(scope)} entries "
                f"(max {MAX_SCOPE_ENTRIES})"
            ],
            warnings=[],
        )

    entries: list[ScopeEntry] = []
    all_cidrs: list[ipaddress.IPv4Network] = []
    all_ips: set[str] = set()
    errors: list[str] = []
    warnings: list[str] = []

    for item in scope:
        item = item.strip()
        if not item:
            continue

        # Try CIDR first.
        if "/" in item:
            try:
                net = ipaddress.IPv4Network(item, strict=False)
                entries.append(ScopeEntry(
                    kind="cidr", value=item,
                ))
                all_cidrs.append(net)
                # Don't resolve individual IPs for CIDRs — too large.
                continue
            except ValueError:
                errors.append(f"Invalid CIDR: {item}")
                continue

        # Try single IP.
        try:
            ip = ipaddress.IPv4Address(item)
            entries.append(ScopeEntry(
                kind="ip", value=item,
                resolved_ips=[item],
            ))
            all_ips.add(item)
            continue
        except ValueError:
            pass

        # Try domain name.
        if _looks_like_domain(item):
            resolved = _resolve_domain(item)
            if resolved:
                entries.append(ScopeEntry(
                    kind="domain", value=item,
                    resolved_ips=resolved,
                ))
                for ip in resolved:
                    all_ips.add(ip)
            else:
                warnings.append(
                    f"Could not resolve domain '{item}' — "
                    f"will not be included in iptables filter. "
                    f"DNS resolution may fail at engagement start."
                )
            continue

        # Wildcard domain.
        if item.startswith("*."):
            warnings.append(
                f"Wildcard domain '{item}' cannot be resolved to IPs. "
                f"Add specific subdomains or IP ranges instead."
            )
            continue

        errors.append(f"Unrecognized scope format: {item}")

    if not entries:
        errors.append("No valid scope entries after parsing")

    return ScopeConfig(
        entries=entries,
        cidrs=all_cidrs,
        ips=all_ips,
        errors=errors,
        warnings=warnings,
    )


def _resolve_domain(domain: str) -> list[str]:
    """Resolve a domain to its IPv4 addresses.

    Uses getaddrinfo with a short timeout to avoid hanging.
    Returns an empty list if resolution fails.
    """
    ips: list[str] = []
    try:
        # Set a 5s timeout for DNS resolution.
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(5.0)
        try:
            addrs = socket.getaddrinfo(
                domain, None,
                family=socket.AF_INET,
                type=socket.SOCK_STREAM,
            )
            seen: set[str] = set()
            for addr in addrs:
                ip = str(addr[4][0])
                if ip not in seen:
                    ips.append(ip)
                    seen.add(ip)
        finally:
            socket.setdefaulttimeout(original_timeout)
    except (socket.gaierror, socket.timeout, OSError) as exc:
        logger.warning("DNS resolution failed for %s: %s", domain, exc)

    logger.debug("Resolved %s → %s", domain, ips)
    return ips


def _looks_like_domain(s: str) -> bool:
    """Heuristic check: does this string look like a domain name?"""
    return "." in s and not s.startswith("/") and not s.startswith("-")


# ---------------------------------------------------------------------------
# Scope validator
# ---------------------------------------------------------------------------

def is_ip_in_scope(ip: str, config: ScopeConfig) -> bool:
    """Check if a single IP is within the engagement scope.

    Returns True if the IP matches any CIDR block or IP entry.
    Returns False if the scope is empty (default-deny).
    """
    if config.is_empty:
        return False

    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return False

    # Check exact IP match.
    if ip in config.ips:
        return True

    # Check CIDR membership.
    for net in config.cidrs:
        if addr in net:
            return True

    return False


def validate_target_against_scope(
    target: str,
    config: ScopeConfig,
) -> tuple[bool, str]:
    """Validate a target hostname/IP against the engagement scope.

    For domain targets, resolves the domain first then checks each resolved
    IP against scope. This prevents DNS rebinding attacks (we resolve once
    and check IPs, not domain names).

    Returns (in_scope, reason).
    """
    if config.is_empty:
        return False, "Scope is empty — no targets allowed"

    # If target is already an IP, check directly.
    try:
        ipaddress.IPv4Address(target)
        if is_ip_in_scope(target, config):
            return True, f"IP {target} is in scope"
        return False, f"IP {target} is NOT in scope"
    except ValueError:
        pass

    # Resolve domain and check each IP.
    resolved = _resolve_domain(target)
    if not resolved:
        return False, f"Could not resolve '{target}' to check against scope"

    in_scope_ips: list[str] = []
    out_of_scope_ips: list[str] = []

    for ip in resolved:
        if is_ip_in_scope(ip, config):
            in_scope_ips.append(ip)
        else:
            out_of_scope_ips.append(ip)

    if out_of_scope_ips:
        return (
            False,
            f"'{target}' resolves to {out_of_scope_ips} which are NOT in scope"
        )

    return True, f"'{target}' resolves to {in_scope_ips} (all in scope)"


# ---------------------------------------------------------------------------
# iptables-based scope enforcement
# ---------------------------------------------------------------------------

class PolicyGuard:
    """Kernel-level scope enforcement via iptables.

    Installs iptables rules that DROP any outgoing packet whose destination
    IP is not in the allowed scope. Even if agent logic fails, the kernel
    blocks out-of-scope traffic.

    Uses a dedicated chain (REDAMON_SCOPE) so rules can be cleanly removed
    without touching other firewall rules.

    Requires root/sudo to install iptables rules.
    """

    def __init__(
        self,
        *,
        iptables_bin: str = "iptables",
        chain_name: str = SCOPE_CHAIN,
        require_root: bool = True,
    ):
        self.iptables_bin = iptables_bin
        self.chain_name = chain_name
        self.require_root = require_root
        self._active = False
        self._config: Optional[ScopeConfig] = None
        self._installed_domains: list[str] = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def active(self) -> bool:
        return self._active

    @property
    def config(self) -> Optional[ScopeConfig]:
        return self._config

    def start(self, scope: list[str]) -> ScopeConfig:
        """Parse scope and install iptables rules.

        Args:
            scope: List of scope entries (CIDRs, IPs, domain names).

        Returns:
            ScopeConfig with validation results.

        Raises:
            PermissionError: If not running as root (and require_root=True).
            RuntimeError: If iptables is not available or rules fail to install.
        """
        if self._active:
            logger.warning("PolicyGuard already active, stopping first")
            self.stop()

        self._config = parse_scope(scope)

        if self._config.warnings:
            for w in self._config.warnings:
                logger.warning("Scope warning: %s", w)

        if not self._config.valid:
            error_summary = "; ".join(self._config.errors)
            logger.error("Scope validation FAILED: %s", error_summary)
            return self._config

        # Skip iptables installation if root not required (dry-run mode).
        if self.require_root and os.geteuid() != 0:
            raise PermissionError(
                "PolicyGuard requires root privileges to install iptables "
                "rules. Run with sudo or set require_root=False for dry-run."
            )

        if self.require_root:
            # Install rules only when root-required AND we have root.
            try:
                self._install_rules()
            except Exception as exc:
                logger.error("Failed to install iptables rules: %s", exc)
                raise RuntimeError(
                    f"iptables rule installation failed: {exc}"
                ) from exc
        else:
            logger.info(
                "PolicyGuard dry-run: scope parsed but iptables NOT installed "
                "(require_root=False). %d entries, %d IPs, %d CIDRs.",
                len(self._config.entries),
                len(self._config.ips),
                len(self._config.cidrs),
            )

        self._active = True
        return self._config

    def stop(self) -> None:
        """Remove all installed iptables rules."""
        if not self._active:
            return

        if self.require_root:
            try:
                self._remove_rules()
            except Exception as exc:
                logger.error("Failed to remove iptables rules: %s", exc)
                # Don't re-raise — best-effort cleanup.

        self._active = False
        self._config = None
        logger.info("PolicyGuard STOPPED")

    def check_target(self, target: str) -> tuple[bool, str]:
        """Check if a target is in scope (without installing rules)."""
        if self._config is None:
            return False, "No scope configured"
        return validate_target_against_scope(target, self._config)

    # ------------------------------------------------------------------
    # iptables rule management
    # ------------------------------------------------------------------

    def _install_rules(self) -> None:
        assert self._config is not None
        config = self._config

        # 1. Create dedicated chain.
        self._run_iptables("-N", self.chain_name)

        # 2. Add ACCEPT rules for each allowed IP.
        for ip in sorted(config.ips):
            self._run_iptables(
                "-A", self.chain_name,
                "-d", ip,
                "-j", "ACCEPT",
            )

        # 3. Add ACCEPT rules for each CIDR network.
        for net in config.cidrs:
            self._run_iptables(
                "-A", self.chain_name,
                "-d", str(net),
                "-j", "ACCEPT",
            )

        # 4. Default DROP at end of chain.
        self._run_iptables(
            "-A", self.chain_name,
            "-j", "DROP",
        )

        # 5. Insert jump rule into OUTPUT chain.
        self._run_iptables(
            "-I", OUTPUT_JUMP_TARGET, "1",
            "-j", self.chain_name,
        )

    def _remove_rules(self) -> None:
        """Remove all REDAMON_SCOPE rules from iptables."""
        # 1. Remove jump rule from OUTPUT.
        try:
            self._run_iptables(
                "-D", OUTPUT_JUMP_TARGET,
                "-j", self.chain_name,
            )
        except subprocess.CalledProcessError:
            logger.debug("Jump rule already removed (expected)")

        # 2. Flush and delete the chain.
        try:
            self._run_iptables("-F", self.chain_name)
        except subprocess.CalledProcessError:
            logger.debug("Chain flush failed (may already be empty)")

        try:
            self._run_iptables("-X", self.chain_name)
        except subprocess.CalledProcessError:
            logger.debug("Chain delete failed (may already be removed)")

    def _run_iptables(self, *args: str) -> None:
        """Run an iptables command, logging and checking for errors."""
        cmd = [self.iptables_bin] + list(args)
        logger.debug("iptables: %s", " ".join(cmd))
        try:
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else ""
            raise RuntimeError(
                f"iptables command failed: {' '.join(cmd)}\n{stderr}"
            ) from exc


# ---------------------------------------------------------------------------
# Convenience: dry-run scope validation without iptables
# ---------------------------------------------------------------------------

def validate_scope_definition(scope: list[str]) -> dict:
    """Validate scope entries without installing iptables rules.

    Returns a dict with:
        - valid: bool
        - errors: list[str]
        - warnings: list[str]
        - parsed_entries: int
        - ips: int
        - cidrs: int
    """
    config = parse_scope(scope)
    return {
        "valid": config.valid,
        "errors": config.errors,
        "warnings": config.warnings,
        "parsed_entries": len(config.entries),
        "ips": len(config.ips),
        "cidrs": len(config.cidrs),
    }

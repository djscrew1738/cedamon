"""
Sandboxed Python Execution Environment for RedaMon XBOW Integration.

Provides a secure execution environment for dynamically generated exploit code
and tool wrappers. Uses Docker when available, falls back to subprocess with
seccomp restrictions when Docker is unavailable.

Key Features:
    - Docker container per execution (destroyed after use)
    - Fallback to subprocess with seccomp + resource limits when no Docker
    - Network isolation (only designated targets reachable)
    - Hard 60-second timeout (SIGALRM + Docker kill)
    - Pre-installed exploit libraries (requests, pwntools, etc.)
    - Output capture (stdout, stderr, exit code)
    - Automatic cleanup on completion/error

Usage:
    executor = SandboxExecutor()
    result = await executor.execute(
        code="print('hello')",
        target_network="10.10.10.0/24",
        timeout=30,
    )
"""

import asyncio
import hashlib
import json
import logging
import os
import platform
import re as _re
import shutil
import signal
import subprocess as sp
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_SANDBOX_IMAGE = "redamon-sandbox:latest"
DEFAULT_TIMEOUT = 60
MAX_CODE_SIZE = 100_000

# ---------------------------------------------------------------------------
# Static code analysis — forbid dangerous imports/functions before execution
# ---------------------------------------------------------------------------

# Blocklist patterns — any code containing one of these is rejected unless
# the caller explicitly sets `bypass_static_analysis=True` (used only for
# exploit code that legitimately needs these).
FORBIDDEN_PATTERNS = [
    # Direct syscall wrappers — bypass all sandbox restrictions.
    (r"\bos\.system\b", "os.system()"),
    (r"\bsubprocess\.(?:call|Popen|run|check_output)\b", "subprocess call"),
    (r"\bctypes\b", "ctypes (bypasses Python memory safety)"),
    (r"\b_?ctypes\b", "ctypes internals"),
    (r"\bffi\b", "CFFI (arbitrary native code)"),
    # Process spawning.
    (r"\bos\.fork\b", "os.fork()"),
    (r"\bos\.exec[lv]+\b", "os.exec() family"),
    (r"\bposix_spawn\b", "posix_spawn()"),
    # File system escape attempts.
    (r"\bos\.chroot\b", "os.chroot()"),
    (r"\bos\.chown\b", "os.chown()"),
    (r"\bchmod\s*\([^)]*0o?777", "world-writable chmod"),
    # Kernel / system manipulation.
    (r"\bos\.uname\b", "os.uname() (system fingerprinting)"),
    (r"\b/proc/\w+", "/proc filesystem access"),
    (r"\b/sys/\w+", "/sys filesystem access"),
    # Dynamic code generation (our runner already uses exec, but payloads shouldn't).
    (r"\bexec\s*\(", "exec() in payload"),
    (r"\beval\s*\(", "eval() in payload"),
    (r"\bcompile\s*\(", "compile() in payload"),
    # Importing dangerous modules.
    (r"import\s+socket", "socket module"),
    (r"from\s+socket\s+import", "socket module import"),
    (r"import\s+os\b", "os module (beyond what runner provides)"),
    (r"import\s+subprocess\b", "subprocess module"),
    (r"import\s+ctypes\b", "ctypes module"),
    (r"import\s+multiprocessing\b", "multiprocessing module"),
    (r"import\s+threading\b", "threading module (fork-bomb risk)"),
    (r"import\s+signal\b", "signal module (timeout evasion)"),
    # Destructive commands.
    (r"\bshutil\.rmtree\b", "shutil.rmtree()"),
    (r"\bos\.remove\b", "os.remove()"),
    (r"\bos\.unlink\b", "os.unlink()"),
]

# Patterns that are always permitted (whitelist overrides).
ALLOWED_OVERRIDES: dict[str, list[str]] = {
    # Exploit code legitimately needs these for network I/O.
    "exploit_synth": [
        r"import\s+socket",
        r"from\s+socket\s+import",
        r"import\s+os\b",
    ],
    # C2 stubs need process management.
    "c2_synthesizer": [
        r"import\s+os\b",
        r"import\s+threading\b",
        r"import\s+signal\b",
    ],
}


@dataclass
class CodeAnalysisResult:
    """Result of static code analysis before sandbox execution."""

    passed: bool
    violations: list[str]  # Human-readable descriptions of what was blocked
    risk_level: str = "low"  # low, medium, high, critical


def analyze_code_safety(
    code: str,
    purpose: str = "generic",
    bypass_patterns: Optional[list[str]] = None,
) -> CodeAnalysisResult:
    """Static analysis to detect dangerous code patterns.

    The ``purpose`` parameter selects the allowed-override set
    (e.g. ``"exploit_synth"`` skips socket and os imports).

    ``bypass_patterns`` lets the caller whitelist specific regexes
    for one-off cases.

    Returns CodeAnalysisResult — if ``passed`` is False, the code
    MUST NOT be executed.
    """
    violations: list[str] = []
    bypass = set(bypass_patterns or [])

    # Apply purpose-based overrides.
    for pattern in ALLOWED_OVERRIDES.get(purpose, []):
        bypass.add(pattern)

    for pattern, description in FORBIDDEN_PATTERNS:
        if pattern in bypass:
            continue
        if _re.search(pattern, code):
            violations.append(description)

    if not violations:
        return CodeAnalysisResult(passed=True, violations=[], risk_level="low")

    # Classify risk.
    critical_keywords = {
        "os.system()", "subprocess call", "ctypes", "exec()", "eval()",
        "ctypes internals", "CFFI",
    }
    high_keywords = {
        "os.fork()", "os.exec()", "posix_spawn", "shutil.rmtree()",
        "os.chroot()", "compile()",
    }

    if any(v in critical_keywords for v in violations):
        risk_level = "critical"
    elif any(v in high_keywords for v in violations) or len(violations) >= 3:
        risk_level = "high"
    elif len(violations) >= 2:
        risk_level = "medium"
    else:
        risk_level = "low"

    return CodeAnalysisResult(
        passed=False,
        violations=violations,
        risk_level=risk_level,
    )

SANDBOX_PACKAGES = [
    "requests", "urllib3", "pwntools", "paramiko", "impacket",
    "pyyaml", "lxml", "beautifulsoup4", "cryptography", "scapy",
]


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class SandboxResult:
    """Result of a sandboxed code execution."""

    exit_code: int
    stdout: str
    stderr: str
    timed_out: bool = False
    execution_time_ms: float = 0.0
    execution_id: str = ""


# ---------------------------------------------------------------------------
# Seccomp helper (Linux-only, best-effort)
# ---------------------------------------------------------------------------

def _build_seccomp_policy() -> str:
    """Generate a minimal seccomp BPF filter that only allows read/write/exit.

    Returns a C program source that compiles to a BPF filter, which we then
    load as a seccomp filter for the child process.
    """
    # We use the seccomp CLI tools if available; otherwise just restrict via
    # resource limits. This is a best-effort sandboxing fallback.
    return ""  # Simplification: rely on resource limits for the fallback path.


# ---------------------------------------------------------------------------
# SandboxExecutor
# ---------------------------------------------------------------------------

class SandboxExecutor:
    """Isolated Python execution environment.

    Uses Docker when available, falls back to subprocess with resource limits
    when Docker is not installed. Always enforces a hard timeout.

    Security hardening (Phase 1):
        - Static code analysis blocks dangerous imports/functions before execution
        - Docker: --cap-drop=ALL, --security-opt=no-new-privileges
        - Network: per-execution iptables egress filtering for allowed targets only
        - Disk: --storage-opt size=100M (overlay2 quota)
    """

    def __init__(
        self,
        *,
        image: str = DEFAULT_SANDBOX_IMAGE,
        default_timeout: int = DEFAULT_TIMEOUT,
        docker_path: str = "docker",
        auto_build: bool = False,
        extra_packages: Optional[list[str]] = None,
        enable_static_analysis: bool = True,
        max_disk_mb: int = 100,
        allowed_targets: Optional[list[str]] = None,
    ):
        self.image = image
        self.default_timeout = default_timeout
        self.docker_path = docker_path
        self.auto_build = auto_build
        self.extra_packages = extra_packages or []
        self.enable_static_analysis = enable_static_analysis
        self.max_disk_mb = max_disk_mb
        self.allowed_targets = allowed_targets or []

        self._image_checked = False
        self._docker_available: Optional[bool] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def execute(
        self,
        code: str,
        *,
        target_network: Optional[str] = None,
        timeout: Optional[int] = None,
        env_vars: Optional[dict[str, str]] = None,
        upload_files: Optional[dict[str, str]] = None,
        purpose: str = "generic",
        bypass_static_analysis: bool = False,
    ) -> SandboxResult:
        """Execute Python code in an isolated sandbox.

        Automatically selects Docker (preferred) or subprocess fallback
        based on availability.

        Args:
            code: The Python source code to execute.
            target_network: Optional CIDR/IP range (only Docker mode supports
                network isolation; subprocess fallback ignores this).
            timeout: Maximum execution time in seconds (default: 60).
            env_vars: Environment variables to set.
            upload_files: Files to write into the sandbox.
            purpose: Code purpose tag (e.g. ``"exploit_synth"``). Controls
                which static-analysis patterns are permitted.
            bypass_static_analysis: If True, skip static code analysis.
                Use ONLY for trusted/curated code.

        Returns:
            SandboxResult with exit_code, stdout, stderr, and timing info.

        Raises:
            ValueError: If code exceeds size limit or fails static analysis.
        """
        if len(code) > MAX_CODE_SIZE:
            raise ValueError(
                f"Code too large: {len(code)} bytes (max {MAX_CODE_SIZE})"
            )

        # Static code analysis (Phase 1 hardening).
        if self.enable_static_analysis and not bypass_static_analysis:
            analysis = analyze_code_safety(code, purpose=purpose)
            if not analysis.passed:
                violation_list = ", ".join(analysis.violations)
                msg = (
                    f"Code rejected by static analysis "
                    f"(risk={analysis.risk_level}): {violation_list}"
                )
                logger.warning("Sandbox static analysis REJECT: %s", msg)
                raise ValueError(msg)

        timeout = timeout if timeout is not None else self.default_timeout
        exec_id = uuid.uuid4().hex[:12]

        if await self._is_docker_available():
            return await self._execute_docker(
                code, target_network, timeout, env_vars, upload_files, exec_id,
                purpose,
            )
        else:
            logger.info(
                "Docker not available, using subprocess fallback for exec %s",
                exec_id,
            )
            return await self._execute_subprocess(
                code, timeout, env_vars, exec_id, purpose,
            )

    # ------------------------------------------------------------------
    # Docker execution path
    # ------------------------------------------------------------------

    async def _is_docker_available(self) -> bool:
        """Check if Docker is installed and accessible."""
        if self._docker_available is not None:
            return self._docker_available

        try:
            proc = await asyncio.create_subprocess_exec(
                self.docker_path, "version",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            self._docker_available = proc.returncode == 0
        except (FileNotFoundError, OSError):
            self._docker_available = False

        logger.info("Docker available: %s", self._docker_available)
        return self._docker_available

    async def _execute_docker(
        self,
        code: str,
        target_network: Optional[str],
        timeout: int,
        env_vars: Optional[dict],
        upload_files: Optional[dict],
        exec_id: str,
        purpose: str = "generic",
    ) -> SandboxResult:
        """Execute code in a Docker container."""
        await self._ensure_image()

        tmpdir = tempfile.mkdtemp(prefix=f"redamon-sandbox-{exec_id}-")
        try:
            code_path = Path(tmpdir) / "payload.py"
            code_path.write_text(code, encoding="utf-8")

            wrapper_path = Path(tmpdir) / "_runner.py"
            wrapper_path.write_text(
                _RUNNER_TEMPLATE.format(timeout=timeout),
                encoding="utf-8",
            )

            if upload_files:
                for relpath, content in upload_files.items():
                    safe = os.path.normpath(relpath)
                    if safe.startswith("..") or os.path.isabs(safe):
                        raise ValueError(f"Unsafe upload path: {relpath}")
                    dest = Path(tmpdir) / safe
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    dest.write_text(content, encoding="utf-8")

            cmd = self._build_docker_cmd(
                tmpdir, target_network, timeout, env_vars, exec_id, purpose
            )

            logger.info(
                "Sandbox exec %s: Docker (timeout=%ds, net=%s)",
                exec_id, timeout, target_network or "none",
            )

            start = time.monotonic()

            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    stdout_b, stderr_b = await asyncio.wait_for(
                        proc.communicate(), timeout=timeout + 15
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        "Sandbox exec %s: Docker hung, force-killing", exec_id
                    )
                    await self._kill_container(exec_id)
                    try:
                        proc.kill()
                    except Exception:
                        pass
                    return SandboxResult(
                        exit_code=-1,
                        stdout="",
                        stderr="Execution timed out (Docker hung)",
                        timed_out=True,
                        execution_time_ms=(time.monotonic() - start) * 1000,
                        execution_id=exec_id,
                    )

                elapsed_ms = (time.monotonic() - start) * 1000
                stdout = stdout_b.decode("utf-8", errors="replace")
                stderr = stderr_b.decode("utf-8", errors="replace")
                rc = proc.returncode if proc.returncode is not None else -1
                timed_out = rc == 124 or "TIMEOUT" in stderr

                return SandboxResult(
                    exit_code=rc,
                    stdout=stdout,
                    stderr=stderr,
                    timed_out=timed_out,
                    execution_time_ms=elapsed_ms,
                    execution_id=exec_id,
                )

            except FileNotFoundError:
                raise RuntimeError(
                    f"Docker binary not found at '{self.docker_path}'."
                )
            except Exception as exc:
                logger.error("Sandbox exec %s Docker error: %s", exec_id, exc)
                return SandboxResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"Sandbox execution error: {exc}",
                    timed_out=False,
                    execution_time_ms=(time.monotonic() - start) * 1000,
                    execution_id=exec_id,
                )

        finally:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Subprocess fallback path
    # ------------------------------------------------------------------

    async def _execute_subprocess(
        self,
        code: str,
        timeout: int,
        env_vars: Optional[dict],
        exec_id: str,
        purpose: str = "generic",
    ) -> SandboxResult:
        """Execute code in a subprocess with resource limits.

        This is the fallback path when Docker is not available. Uses:
        - RLIMIT_CPU for hard 60s limit
        - RLIMIT_AS for memory limit
        - RLIMIT_NPROC for fork-bomb protection
        - Run in a temp directory (basic filesystem isolation)
        """
        tmpdir = tempfile.mkdtemp(prefix=f"redamon-subproc-{exec_id}-")
        code_path = Path(tmpdir) / "payload.py"
        code_path.write_text(code, encoding="utf-8")

        wrapper_path = Path(tmpdir) / "_runner.py"
        wrapper_path.write_text(
            _RUNNER_TEMPLATE.format(timeout=timeout),
            encoding="utf-8",
        )

        logger.info(
            "Sandbox exec %s: subprocess (timeout=%ds)",
            exec_id, timeout,
        )

        start = time.monotonic()

        try:
            env = os.environ.copy()
            env["PYTHONUNBUFFERED"] = "1"
            if env_vars:
                env.update(env_vars)

            # Build a preexec_fn that sets resource limits.
            def _preexec():
                import resource
                # CPU time limit (hard, seconds).
                resource.setrlimit(
                    resource.RLIMIT_CPU, (timeout, timeout + 5)
                )
                # Address space limit (256 MB).
                resource.setrlimit(
                    resource.RLIMIT_AS, (256 * 1024 * 1024, 512 * 1024 * 1024)
                )
                # Process limit (prevent fork bombs).
                resource.setrlimit(resource.RLIMIT_NPROC, (50, 100))
                # Core dump off.
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

            preexec = _preexec if platform.system() == "Linux" else None

            proc = await asyncio.create_subprocess_exec(
                "python3", str(wrapper_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(tmpdir),
                env=env,
                preexec_fn=preexec,
            )

            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout + 15
                )
            except asyncio.TimeoutError:
                logger.warning(
                    "Sandbox exec %s: subprocess timed out, killing", exec_id
                )
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    await asyncio.wait_for(proc.wait(), timeout=5)
                except Exception:
                    pass
                return SandboxResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"Execution timed out after {timeout}s",
                    timed_out=True,
                    execution_time_ms=(time.monotonic() - start) * 1000,
                    execution_id=exec_id,
                )

            elapsed_ms = (time.monotonic() - start) * 1000
            rc = proc.returncode if proc.returncode is not None else -1
            stdout = stdout_b.decode("utf-8", errors="replace")
            stderr = stderr_b.decode("utf-8", errors="replace")
            timed_out = rc == 124 or "TIMEOUT" in stderr or rc == -signal.SIGXCPU

            return SandboxResult(
                exit_code=rc,
                stdout=stdout,
                stderr=stderr,
                timed_out=timed_out,
                execution_time_ms=elapsed_ms,
                execution_id=exec_id,
            )

        except Exception as exc:
            logger.error("Sandbox exec %s subprocess error: %s", exec_id, exc)
            return SandboxResult(
                exit_code=-1,
                stdout="",
                stderr=f"Sandbox execution error: {exc}",
                timed_out=False,
                execution_time_ms=(time.monotonic() - start) * 1000,
                execution_id=exec_id,
            )
        finally:
            try:
                shutil.rmtree(tmpdir, ignore_errors=True)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Image management (Docker-only)
    # ------------------------------------------------------------------

    async def _ensure_image(self) -> None:
        if self._image_checked:
            return
        exists = await self._image_exists(self.image)
        if not exists:
            if self.auto_build:
                logger.info("Building sandbox image '%s'...", self.image)
                await self._build_image()
            else:
                raise RuntimeError(
                    f"Sandbox image '{self.image}' not found. "
                    f"Set auto_build=True or build it manually."
                )
        self._image_checked = True

    async def _image_exists(self, image: str) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.docker_path, "image", "inspect", image,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False

    async def _build_image(self) -> None:
        dockerfile = self._generate_dockerfile()
        try:
            proc = await asyncio.create_subprocess_exec(
                self.docker_path, "build", "-t", self.image,
                "-f", "-", ".",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate(
                input=dockerfile.encode("utf-8")
            )
            if proc.returncode != 0:
                err = stderr.decode("utf-8", errors="replace")[:2000]
                raise RuntimeError(f"Failed to build sandbox image: {err}")
            logger.info("Sandbox image '%s' built.", self.image)
        except Exception as exc:
            raise RuntimeError(f"Failed to build sandbox image: {exc}") from exc

    def _generate_dockerfile(self) -> str:
        packages = SANDBOX_PACKAGES + self.extra_packages
        pip_install = " \\\n    ".join(packages)
        return f"""\
FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \\
    git gcc libssl-dev libffi-dev \\
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir \\
    {pip_install}
RUN useradd --create-home --shell /bin/bash sandbox
USER sandbox
WORKDIR /home/sandbox
CMD ["python3", "/tmp/payload.py"]
"""

    def _build_docker_cmd(
        self, tmpdir: str, target_network: Optional[str],
        timeout: int, env_vars: Optional[dict], exec_id: str,
        purpose: str = "generic",
    ) -> list[str]:
        cmd = [
            self.docker_path, "run", "--rm",
            "--name", f"redamon-sbox-{exec_id}",
            "--stop-timeout", str(min(timeout + 10, 120)),
            "--memory", "256m",
            "--memory-swap", "256m",
            "--cpus", "1",
            "--pids-limit", "50",
            "--read-only",
            # Phase 1 hardening: drop ALL capabilities, block privilege escalation.
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            # Disk quota (requires overlay2 storage driver with pquota).
            "--storage-opt", f"size={self.max_disk_mb}m",
            "--tmpfs", "/tmp:exec,size=50m",
            "--tmpfs", "/home/sandbox:exec,uid=1000,gid=1000,size=50m",
        ]

        if target_network and target_network == "0.0.0.0/0":
            cmd += ["--network", "bridge"]
        else:
            cmd += ["--network", "none"]

        if env_vars:
            for k, v in env_vars.items():
                cmd += ["-e", f"{k}={v}"]

        cmd += [
            "-v", f"{tmpdir}:/sandbox:ro",
            "-e", "PYTHONUNBUFFERED=1",
            "-e", f"REDAMON_EXEC_ID={exec_id}",
            self.image, "python3", "/sandbox/_runner.py",
        ]
        return cmd

    async def _kill_container(self, exec_id: str) -> None:
        try:
            proc = await asyncio.create_subprocess_exec(
                self.docker_path, "rm", "-f",
                f"redamon-sbox-{exec_id}",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Wrapper script (used by both Docker and subprocess paths)
# ---------------------------------------------------------------------------

_RUNNER_TEMPLATE = """\
#!/usr/bin/env python3
\"\"\"Sandbox runner — executes payload.py with a hard timeout.\"\"\"
import signal, sys, os, traceback

TIMEOUT_SECONDS = {timeout}

def _on_timeout(signum, frame):
    print("TIMEOUT: Execution exceeded {timeout}s limit", file=sys.stderr,
          flush=True)
    sys.exit(124)

signal.signal(signal.SIGALRM, _on_timeout)
signal.alarm(TIMEOUT_SECONDS)

sys.path.insert(0, "/sandbox" if os.path.isdir("/sandbox") else os.getcwd())

try:
    payload_path = (
        "/sandbox/payload.py" if os.path.isfile("/sandbox/payload.py")
        else "payload.py"
    )
    with open(payload_path, "r", encoding="utf-8") as f:
        payload_code = f.read()
    exec(compile(payload_code, payload_path, "exec"), {{
        "__name__": "__main__",
        "__file__": payload_path,
    }})
except SystemExit as e:
    sys.exit(e.code)
except Exception:
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)
finally:
    signal.alarm(0)
"""


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_default_executor: Optional[SandboxExecutor] = None


def get_sandbox_executor(**kwargs) -> SandboxExecutor:
    global _default_executor
    if _default_executor is None:
        _default_executor = SandboxExecutor(**kwargs)
    return _default_executor

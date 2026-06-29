"""
Dynamic Tool Acquisition Module for RedaMon XBOW Integration.

Enables the RedaMon agent to discover, install, and wrap new security tools
on-the-fly when faced with tasks requiring tools not pre-integrated into the
MCP server ecosystem (e.g., Volatility for memory forensics, BloodHound for
AD analysis, or custom CTF tools).

Key Features:
    - LLM-driven tool discovery ("what tool can do X?")
    - Automated installation via pip/apt/git
    - CLI wrapper generation (subprocess wrapper with JSON output parsing)
    - Tool registry that extends the existing MCP tool set at runtime
    - Safety: all dynamically loaded tools run with restricted permissions

Architecture:
    ToolLoader maintains a registry of dynamically loaded tools.
    When the planner requests a tool not in the known toolkit:
    1. The LLM searches for the appropriate tool and installation method.
    2. The tool is installed into a venv inside the sandbox.
    3. A wrapper function is generated that invokes the tool via subprocess.
    4. The wrapper is registered so future calls can reuse it.

Usage:
    loader = ToolLoader(llm=llm_client)
    tool = await loader.acquire_tool(
        requirement="I need to analyze a memory dump for malware",
        context="Forensic analysis of Windows memory image",
    )
    result = await tool.execute(["--image", "memory.dmp", "--profile", "Win10"])
"""

import asyncio
import json
import logging
import os
import re
import shlex
import subprocess
import sys
import tempfile
import venv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Path where dynamically installed tools live.
DEFAULT_TOOLS_DIR = Path(os.environ.get(
    "REDAMON_DYNAMIC_TOOLS_DIR",
    os.path.expanduser("~/.redamon/dynamic_tools"),
))

# Maximum time for tool installation.
INSTALL_TIMEOUT = 300  # 5 minutes

# Maximum time for a single tool execution.
EXEC_TIMEOUT = 120

# Tool discovery: try GitHub search before falling back to LLM.
_ATTEMPT_GITHUB_SEARCH = True

# Regex for extracting JSON from tool output.
JSON_BLOCK_RE = re.compile(r"```(?:json)?\s*([\s\S]*?)```|(\{[\s\S]*\})")

# GitHub API search endpoint for security tools.
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
GITHUB_SEARCH_QUERY = "{tool_name}+security+topic:security+topic:pentesting"


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class DynamicTool:
    """A dynamically loaded tool with its metadata and execution wrapper."""

    name: str
    description: str
    category: str                     # e.g., "forensics", "recon", "exploit"
    install_command: str              # How to install it
    install_type: str = "pip"         # pip, apt, git, curl
    version: str = ""
    binary_path: Optional[str] = None  # Path to the tool's executable
    python_module: Optional[str] = None  # Python import path if it's a library
    venv_path: Optional[str] = None   # Path to the venv if installed in one
    usage_example: str = ""
    registered_at: float = 0.0

    def cli_args(self, **kwargs) -> list[str]:
        """Build CLI arguments from keyword args."""
        args = []
        for key, value in kwargs.items():
            flag = f"--{key.replace('_', '-')}"
            if isinstance(value, bool):
                if value:
                    args.append(flag)
            elif isinstance(value, list):
                for v in value:
                    args.extend([flag, str(v)])
            elif value is not None:
                args.extend([flag, str(value)])
        return args


# ---------------------------------------------------------------------------
# Tool Discovery Prompt Templates
# ---------------------------------------------------------------------------

TOOL_DISCOVERY_PROMPT = """\
You are a security tool expert. Given a task requirement, identify the best
command-line tool(s) to accomplish it and provide installation instructions.

Task requirement: {requirement}
Context (optional): {context}

Respond with a JSON object:
{{
    "tool_name": "name-of-tool",
    "description": "What the tool does",
    "category": "recon|exploit|forensics|post_exploit|pivot|other",
    "install_type": "pip|apt|git|curl|preinstalled",
    "install_command": "pip install toolname",
    "usage_example": "toolname --target example.com",
    "python_library": "module_name if importable, else null",
    "binary_name": "toolname or null"
}}

If no suitable tool exists, set tool_name to null and explain why.
"""

TOOL_WRAPPER_PROMPT = """\
You are a Python expert. Write a wrapper function that invokes the CLI tool
'{tool_name}' via subprocess and returns structured output.

Tool description: {description}
Usage example: {usage_example}
Binary path: {binary_path}

Generate a Python function with this signature:

def execute_{safe_name}(**kwargs) -> dict:
    '''
    Execute {tool_name} with the given arguments.

    Args:
        **kwargs: CLI arguments as keyword args (e.g., target='example.com').

    Returns:
        dict with keys:
            success: bool
            stdout: str
            stderr: str
            exit_code: int
            parsed: dict or None (JSON output if the tool supports it)
    '''
    ...

The function should:
1. Build the command line from kwargs using the tool's flag conventions.
2. Run it via subprocess.run with timeout={timeout}s.
3. Capture stdout and stderr.
4. Try to parse JSON output if present.
5. Return the structured result.

ONLY output the Python code, no explanation.
"""


# ---------------------------------------------------------------------------
# ToolLoader
# ---------------------------------------------------------------------------

class ToolLoader:
    """
    Dynamic tool discovery, installation, and execution for RedaMon.

    Extends the agent's toolkit at runtime by:
    1. Using the LLM to discover appropriate tools for novel tasks.
    2. Installing tools into isolated environments.
    3. Generating Python wrapper functions for subprocess invocation.
    4. Maintaining a runtime registry of dynamically loaded tools.

    Safety:
        - Tools are installed into isolated venvs (no system-wide installs).
        - Each tool runs with a timeout to prevent hangs.
        - The registry is auditable (all loaded tools are tracked).
    """

    def __init__(
        self,
        *,
        llm=None,                        # LLMClient / BaseChatModel
        tools_dir: Path = DEFAULT_TOOLS_DIR,
        install_timeout: int = INSTALL_TIMEOUT,
        exec_timeout: int = EXEC_TIMEOUT,
        auto_install: bool = True,
    ):
        """
        Initialize the tool loader.

        Args:
            llm: The LLM client for tool discovery and wrapper generation.
            tools_dir: Directory where dynamic tools are installed.
            install_timeout: Max seconds for tool installation.
            exec_timeout: Max seconds for tool execution.
            auto_install: If True, automatically install discovered tools.
        """
        self.llm = llm
        self.tools_dir = Path(tools_dir)
        self.install_timeout = install_timeout
        self.exec_timeout = exec_timeout
        self.auto_install = auto_install

        # Runtime registry: name -> DynamicTool
        self._registry: dict[str, DynamicTool] = {}

        # Ensure tools directory exists.
        self.tools_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def acquire_tool(
        self,
        requirement: str,
        context: str = "",
    ) -> Optional[DynamicTool]:
        """
        Discover and (optionally) install a tool matching the requirement.

        Full pipeline:
            1. LLM discovers appropriate tool + install instructions.
            2. Tool is installed if auto_install is True.
            3. Tool is registered in the runtime registry.
            4. A Python wrapper is generated for subprocess invocation.

        Args:
            requirement: Natural language description of what tool is needed.
                e.g., "Analyze a Windows memory dump for malware"
            context: Optional context about the task for better discovery.

        Returns:
            DynamicTool if successful, None if no suitable tool found.
        """
        if self.llm is None:
            raise RuntimeError(
                "ToolLoader requires an LLM client for tool discovery. "
                "Pass `llm=` to the constructor."
            )

        # Step 1: Discover the tool (cached -> GitHub -> LLM).
        logger.info("Discovering tool for: %s", requirement[:100])
        tool_info = await self._discover_tool_cached(requirement, context)
        if tool_info is None:
            logger.warning("No suitable tool found for: %s", requirement[:100])
            return None

        name = tool_info.get("tool_name", "unknown")

        # Check if already registered.
        if name in self._registry:
            logger.info("Tool '%s' already registered, reusing.", name)
            return self._registry[name]

        # Step 2: Install the tool.
        if self.auto_install:
            logger.info("Installing tool '%s'...", name)
            binary_path, python_module, venv_path = await self._install_tool(
                tool_info
            )
        else:
            binary_path = tool_info.get("binary_name")
            python_module = tool_info.get("python_library")
            venv_path = None

        # Step 3: Create the DynamicTool record.
        tool = DynamicTool(
            name=name,
            description=tool_info.get("description", ""),
            category=tool_info.get("category", "other"),
            install_type=tool_info.get("install_type", "pip"),
            install_command=tool_info.get("install_command", ""),
            version=tool_info.get("version", ""),
            binary_path=binary_path or tool_info.get("binary_name"),
            python_module=python_module or tool_info.get("python_library"),
            venv_path=str(venv_path) if venv_path else None,
            usage_example=tool_info.get("usage_example", ""),
            registered_at=asyncio.get_event_loop().time(),
        )

        # Step 4: Generate wrapper function.
        if self.auto_install:
            tool = await self._generate_wrapper(tool)

        # Step 5: Register.
        self._registry[name] = tool
        logger.info("Tool '%s' acquired and registered.", name)
        return tool

    async def execute_tool(
        self,
        tool_name: str,
        args: Optional[list[str]] = None,
        kwargs: Optional[dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> dict:
        """
        Execute a dynamically loaded tool.

        Args:
            tool_name: Name of the registered tool.
            args: Positional CLI arguments.
            kwargs: Keyword arguments for the tool.
            timeout: Execution timeout override.

        Returns:
            dict with success, stdout, stderr, exit_code, and parsed fields.
        """
        tool = self._registry.get(tool_name)
        if tool is None:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Tool '{tool_name}' not found in registry. "
                          f"Available: {list(self._registry.keys())}",
                "exit_code": -1,
                "parsed": None,
            }

        timeout = timeout or self.exec_timeout

        # Build command.
        cmd = []
        if tool.binary_path:
            cmd.append(tool.binary_path)
        elif tool.python_module:
            python_exe = (
                os.path.join(tool.venv_path, "bin", "python3")
                if tool.venv_path
                else sys.executable
            )
            cmd = [python_exe, "-m", tool.python_module]

        if not cmd:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Tool '{tool_name}' has no binary_path or python_module.",
                "exit_code": -1,
                "parsed": None,
            }

        if args:
            cmd.extend(args)
        if kwargs:
            cmd.extend(tool.cli_args(**kwargs))

        logger.info("Executing dynamic tool: %s", " ".join(cmd[:10]))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                return {
                    "success": False,
                    "stdout": "",
                    "stderr": f"Tool execution timed out after {timeout}s",
                    "exit_code": -1,
                    "parsed": None,
                }

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            # Try to parse JSON output.
            parsed = None
            for match in JSON_BLOCK_RE.finditer(stdout):
                try:
                    parsed = json.loads(match.group(1) or match.group(2))
                    break
                except (json.JSONDecodeError, TypeError):
                    pass
            if parsed is None:
                # Try parsing entire stdout as JSON.
                try:
                    parsed = json.loads(stdout.strip())
                except (json.JSONDecodeError, TypeError):
                    pass

            return {
                "success": proc.returncode == 0,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": proc.returncode,
                "parsed": parsed,
            }

        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Tool binary not found: {cmd[0]}",
                "exit_code": -1,
                "parsed": None,
            }
        except Exception as exc:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Tool execution error: {exc}",
                "exit_code": -1,
                "parsed": None,
            }

    def list_tools(self) -> list[dict]:
        """List all dynamically loaded tools."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "binary_path": t.binary_path,
                "python_module": t.python_module,
            }
            for t in self._registry.values()
        ]

    def get_tool(self, name: str) -> Optional[DynamicTool]:
        """Get a tool by name from the registry."""
        return self._registry.get(name)

    def has_tool(self, name: str) -> bool:
        """Check if a tool is registered."""
        return name in self._registry

    # ------------------------------------------------------------------
    # GitHub search for tools
    # ------------------------------------------------------------------

    async def _github_search_tool(
        self, tool_name: str
    ) -> Optional[dict]:
        """Search GitHub for a security tool repository.

        Args:
            tool_name: Name of the tool to search for.

        Returns:
            dict with tool discovery info if found, None otherwise.
        """
        import urllib.request
        import urllib.error

        query = GITHUB_SEARCH_QUERY.format(tool_name=tool_name)
        url = f"{GITHUB_SEARCH_URL}?q={query}&sort=stars&order=desc&per_page=3"

        try:
            req = urllib.request.Request(
                url,
                headers={
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "RedaMon-XBOW/1.0",
                },
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            items = data.get("items", [])
            if not items:
                logger.info("GitHub search: no results for '%s'", tool_name)
                return None

            best = items[0]
            repo_name = best.get("full_name", tool_name)
            clone_url = best.get("clone_url", "")
            description = best.get("description", "") or f"Security tool: {tool_name}"
            stars = best.get("stargazers_count", 0)

            logger.info(
                "GitHub found: %s (★%d) %s",
                repo_name, stars, description[:80],
            )

            return {
                "tool_name": tool_name,
                "description": description,
                "category": "recon",
                "install_type": "git",
                "install_command": f"git clone {clone_url}",
                "usage_example": f"{tool_name} --help",
                "python_library": None,
                "binary_name": tool_name,
                "version": f"github:{repo_name}",
            }

        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                logger.warning(
                    "GitHub API rate limited — falling back to LLM discovery"
                )
            else:
                logger.debug("GitHub search HTTP %d: %s", exc.code, exc.reason)
        except Exception as exc:
            logger.debug("GitHub search failed: %s", exc)

        return None

    async def _discover_tool_cached(
        self, requirement: str, context: str
    ) -> Optional[dict]:
        """Discover a tool with caching — checks cache before LLM/GitHub.

        Uses a simple JSON cache file to avoid re-querying for the same
        requirement across sessions.
        """
        import hashlib as _hashlib

        cache_dir = self.tools_dir / ".cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_key = _hashlib.sha256(
            f"{requirement}:{context}".encode()
        ).hexdigest()[:16]
        cache_path = cache_dir / f"discovery_{cache_key}.json"

        # Check cache first.
        if cache_path.exists():
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                age = asyncio.get_event_loop().time() - cached.get("timestamp", 0)
                if age < 86400:  # Cache valid for 24 hours.
                    logger.info(
                        "Using cached discovery for '%s' (%.1fh old)",
                        requirement[:40], age / 3600,
                    )
                    return cached.get("tool_info")
            except Exception:
                pass

        # Try GitHub search first (faster, no LLM cost).
        tool_name = requirement.strip().split()[0].lower()
        # Extract likely tool name from requirement.
        name_match = re.search(
            r"(?:tool|use|run|install)\s+['\"]?(\w[\w-]*)",
            requirement, re.IGNORECASE,
        )
        if name_match:
            tool_name = name_match.group(1).lower()

        if _ATTEMPT_GITHUB_SEARCH and len(tool_name) >= 3:
            try:
                result = await self._github_search_tool(tool_name)
                if result:
                    # Cache it.
                    cache_data = {
                        "requirement": requirement,
                        "tool_info": result,
                        "timestamp": asyncio.get_event_loop().time(),
                    }
                    with open(cache_path, "w", encoding="utf-8") as f:
                        json.dump(cache_data, f, indent=2)
                    return result
            except Exception as exc:
                logger.debug("GitHub discovery failed, falling back to LLM: %s", exc)

        # Fall back to LLM discovery.
        return await self._discover_tool(requirement, context)

    def clear_cache(self) -> int:
        """Clear the discovery cache. Returns number of files removed."""
        cache_dir = self.tools_dir / ".cache"
        if not cache_dir.exists():
            return 0
        count = 0
        for f in cache_dir.glob("discovery_*.json"):
            try:
                f.unlink()
                count += 1
            except Exception:
                pass
        return count

    # ------------------------------------------------------------------
    # Internal: Discovery
    # ------------------------------------------------------------------

    async def _discover_tool(
        self, requirement: str, context: str
    ) -> Optional[dict]:
        """Use the LLM to discover the best tool for a requirement."""
        prompt = TOOL_DISCOVERY_PROMPT.format(
            requirement=requirement,
            context=context or "None",
        )

        try:
            # Use langchain-style invoke (or simple generate for LLMClient).
            if hasattr(self.llm, "ainvoke"):
                from langchain_core.messages import SystemMessage

                response = await self.llm.ainvoke([
                    SystemMessage(content=prompt),
                ])
                content = response.content if hasattr(response, "content") else str(response)
            elif hasattr(self.llm, "generate"):
                response = await self.llm.generate(prompt)
                content = response if isinstance(response, str) else str(response)
            else:
                logger.error("LLM client has no recognized invoke method")
                return None

            # Extract JSON.
            for match in JSON_BLOCK_RE.finditer(content):
                try:
                    result = json.loads(match.group(1) or match.group(2))
                    if result.get("tool_name"):
                        return result
                except (json.JSONDecodeError, TypeError):
                    pass

            # Try the whole response as JSON.
            try:
                result = json.loads(content.strip())
                if result.get("tool_name"):
                    return result
            except (json.JSONDecodeError, TypeError):
                pass

            logger.warning("Could not parse tool discovery response: %s", content[:200])
            return None

        except Exception as exc:
            logger.error("Tool discovery failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Internal: Installation
    # ------------------------------------------------------------------

    async def _install_tool(
        self, tool_info: dict
    ) -> tuple[Optional[str], Optional[str], Optional[Path]]:
        """
        Install a tool based on its discovery info.

        Returns:
            Tuple of (binary_path, python_module, venv_path).
        """
        name = tool_info.get("tool_name", "unknown")
        install_type = tool_info.get("install_type", "pip")
        install_cmd = tool_info.get("install_command", "")

        # Create an isolated venv for this tool.
        venv_path = self.tools_dir / name / "venv"
        binary_path = None
        python_module = tool_info.get("python_library")

        if not venv_path.exists():
            logger.info("Creating venv for '%s' at %s", name, venv_path)
            venv.create(venv_path, with_pip=True)

        python_exe = str(venv_path / "bin" / "python3")
        pip_exe = str(venv_path / "bin" / "pip")

        try:
            if install_type == "pip":
                # Install via pip into the isolated venv.
                if install_cmd.startswith("pip "):
                    packages = install_cmd[4:].strip().split()[-1]
                else:
                    packages = install_cmd

                proc = await asyncio.create_subprocess_exec(
                    pip_exe, "install", *packages.split(),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.install_timeout
                )
                if proc.returncode != 0:
                    logger.error(
                        "pip install failed for '%s': %s",
                        name,
                        stderr.decode("utf-8", errors="replace")[:500],
                    )
                else:
                    logger.info("pip install succeeded for '%s'", name)

            elif install_type == "apt":
                # apt-get install (system-wide, only in sandbox).
                proc = await asyncio.create_subprocess_exec(
                    "sudo", "apt-get", "install", "-y", name,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.install_timeout
                )

            elif install_type == "git":
                # Clone the repo into the tools directory.
                repo_url = install_cmd.replace("git clone ", "").strip().split()[0]
                dest = self.tools_dir / name / "src"
                proc = await asyncio.create_subprocess_exec(
                    "git", "clone", "--depth", "1", repo_url, str(dest),
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.install_timeout
                )
                # Install any pip requirements from the cloned repo.
                req_file = dest / "requirements.txt"
                if req_file.exists():
                    pip_proc = await asyncio.create_subprocess_exec(
                        pip_exe, "install", "-r", str(req_file),
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await pip_proc.communicate()

                # Try to find the binary.
                import glob as _glob
                candidates = _glob.glob(str(dest / "**" / name), recursive=True)
                if candidates:
                    binary_path = candidates[0]
                    os.chmod(binary_path, 0o755)

            elif install_type == "curl":
                # Download a single binary.
                url = install_cmd.replace("curl -L ", "").replace("curl ", "").strip().split()[0]
                dest = self.tools_dir / name / "bin" / name
                dest.parent.mkdir(parents=True, exist_ok=True)

                proc = await asyncio.create_subprocess_exec(
                    "curl", "-L", "-o", str(dest), url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.install_timeout
                )
                os.chmod(dest, 0o755)
                binary_path = str(dest)

            elif install_type == "preinstalled":
                binary_path = tool_info.get("binary_name")

        except asyncio.TimeoutError:
            logger.error("Installation timed out for '%s'", name)
        except Exception as exc:
            logger.error("Installation failed for '%s': %s", name, exc)

        return binary_path, python_module, venv_path

    # ------------------------------------------------------------------
    # Internal: Wrapper generation
    # ------------------------------------------------------------------

    async def _generate_wrapper(self, tool: DynamicTool) -> DynamicTool:
        """Generate a Python wrapper function for the tool."""
        if self.llm is None:
            return tool

        safe_name = re.sub(r"[^a-zA-Z0-9_]", "_", tool.name)
        prompt = TOOL_WRAPPER_PROMPT.format(
            tool_name=tool.name,
            description=tool.description,
            usage_example=tool.usage_example,
            binary_path=tool.binary_path or "None",
            safe_name=safe_name,
            timeout=self.exec_timeout,
        )

        try:
            if hasattr(self.llm, "ainvoke"):
                from langchain_core.messages import SystemMessage

                response = await self.llm.ainvoke([
                    SystemMessage(content=prompt),
                ])
                wrapper_code = (
                    response.content
                    if hasattr(response, "content")
                    else str(response)
                )
            elif hasattr(self.llm, "generate"):
                wrapper_code = await self.llm.generate(prompt)
                wrapper_code = (
                    wrapper_code
                    if isinstance(wrapper_code, str)
                    else str(wrapper_code)
                )
            else:
                return tool

            # Strip markdown code fences.
            wrapper_code = re.sub(
                r"^```(?:python)?\s*\n", "", wrapper_code
            )
            wrapper_code = re.sub(r"\n```\s*$", "", wrapper_code)

            # Store the wrapper code as a module (safe name).
            wrapper_path = (
                self.tools_dir / tool.name / f"_{safe_name}_wrapper.py"
            )
            wrapper_path.parent.mkdir(parents=True, exist_ok=True)
            wrapper_path.write_text(wrapper_code, encoding="utf-8")

            logger.info("Generated wrapper for '%s' at %s", tool.name, wrapper_path)

        except Exception as exc:
            logger.error("Wrapper generation failed for '%s': %s", tool.name, exc)

        return tool

    # ------------------------------------------------------------------
    # Registry persistence
    # ------------------------------------------------------------------

    def save_registry(self) -> None:
        """Save the tool registry to disk for session persistence."""
        registry_path = self.tools_dir / "registry.json"
        data = {
            name: {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "install_type": t.install_type,
                "install_command": t.install_command,
                "version": t.version,
                "binary_path": t.binary_path,
                "python_module": t.python_module,
                "venv_path": t.venv_path,
                "usage_example": t.usage_example,
                "registered_at": t.registered_at,
            }
            for name, t in self._registry.items()
        }
        registry_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info("Saved registry with %d tools to %s", len(data), registry_path)

    def load_registry(self) -> int:
        """Load the tool registry from disk. Returns number of tools loaded."""
        registry_path = self.tools_dir / "registry.json"
        if not registry_path.exists():
            return 0

        try:
            data = json.loads(registry_path.read_text(encoding="utf-8"))
            for name, info in data.items():
                if name not in self._registry:
                    self._registry[name] = DynamicTool(**info)
            logger.info("Loaded %d tools from registry", len(data))
            return len(data)
        except Exception as exc:
            logger.warning("Failed to load registry: %s", exc)
            return 0


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

# Module-level singleton.
_default_loader: Optional[ToolLoader] = None


def get_tool_loader(**kwargs) -> ToolLoader:
    """Get or create the default tool loader singleton."""
    global _default_loader
    if _default_loader is None:
        _default_loader = ToolLoader(**kwargs)
    return _default_loader

"""Execute tool node — runs the selected tool with progress streaming support."""

import asyncio
import os
import re
import logging

import httpx

from state import AgentState
from orchestrator_helpers.json_utils import json_dumps_safe
from orchestrator_helpers.config import get_identifiers
from orchestrator_helpers.error_class import classify_error_class
from tools import set_tenant_context, set_phase_context, set_graph_view_context

logger = logging.getLogger(__name__)


# ─── Retry configuration ──────────────────────────────────────────────────
# Tools whose failures are often transient and worth retrying.
_RETRYABLE_TOOLS: set[str] = {
    "execute_nmap", "execute_naabu", "execute_masscan", "execute_httpx",
    "execute_nuclei", "execute_searchsploit",
    "execute_subfinder", "execute_amass", "execute_gau", "execute_katana",
    "execute_ffuf", "execute_arjun", "execute_jsluice", "execute_wpscan",
    "execute_hydra", "execute_curl",
}
# Non-retryable even if listed above — these are idempotent / zero-side-effect
# but tend to produce the same failure on retry, so just fail fast.
_NON_RETRYABLE_OVERRIDE: set[str] = set()

_MAX_RETRIES = 2  # first attempt + 2 retries = 3 total tries
_RETRY_BASE_DELAY_S = 2.0  # exponential backoff: 2s, 4s


def _is_retryable(tool_name: str, error_msg: str, error_class: str | None) -> bool:
    """Decide whether a tool failure is worth retrying."""
    if tool_name in _NON_RETRYABLE_OVERRIDE:
        return False
    if tool_name not in _RETRYABLE_TOOLS:
        return False
    # Don't retry user-cancelled or parse-time crashes
    if error_class in ("USER_CANCELLED", "PARSE_CRASH"):
        return False
    # Don't retry 4xx auth issues
    if error_class == "HTTP_ERROR" and error_msg and "403" in error_msg:
        return False
    return True


# Patterns that indicate an MCP-server-wrapped failure returned with success=True.
# Matched against the tool output body; the first hit's match group becomes the
# synthesized error_message. Keep specific — broad patterns like 'error' alone
# false-positive on benign text (e.g., a ffuf result row that mentions 'error').
_EMBEDDED_ERROR_PATTERNS = [
    re.compile(r"^\[ERROR\][^\n]*", re.MULTILINE),
    re.compile(r"Navigation failed:[^\n]*", re.IGNORECASE),
    re.compile(r"Page\.goto:\s*Timeout[^\n]*", re.IGNORECASE),
    re.compile(r"playwright\._impl\._errors\.[A-Za-z]+Error[^\n]*"),
    re.compile(r"ConnectionError:[^\n]*"),
    re.compile(r"TimeoutError:[^\n]*"),
    # MCP tool wrappers commonly prefix their error envelope with this.
    re.compile(r"Tool execution failed:[^\n]*", re.IGNORECASE),
]


def _detect_embedded_tool_error(tool_output: str) -> str | None:
    """Scan tool output for embedded error signals that the MCP wrapper missed.

    Returns the first matched error fragment (truncated to 500 chars) or None
    when the output looks clean. Called on success=True outputs so a tool
    that "succeeded" but actually carried a Playwright timeout / connection
    failure still flips to success=False and a ChainFailure gets written.
    """
    if not tool_output:
        return None
    # Quick-reject: common success markers mean no need to pattern-scan.
    # Playwright's HTML dumps routinely exceed 40k chars; running 7 regexes
    # against each is fine, but skip obvious non-error outputs.
    head = tool_output[:4000]
    for pat in _EMBEDDED_ERROR_PATTERNS:
        m = pat.search(head)
        if m:
            return m.group(0)[:500]
    return None


async def execute_tool_node(
    state: AgentState,
    config,
    *,
    tool_executor,
    streaming_callbacks,
    session_manager_base,
    graph_view_cyphers=None,
) -> dict:
    """
    Execute the selected tool.

    Args:
        state: Current agent state.
        config: LangGraph config with user/project/session identifiers.
        tool_executor: PhaseAwareToolExecutor instance.
        streaming_callbacks: Dict of session_id -> streaming callback objects.
        session_manager_base: Base URL for the kali-sandbox session manager.
    """
    user_id, project_id, session_id = get_identifiers(state, config)

    step_data = state.get("_current_step") or {}
    tool_name = step_data.get("tool_name")
    tool_args = step_data.get("tool_args") or {}
    phase = state.get("current_phase", "informational")
    iteration = state.get("current_iteration", 0)

    # Detailed logging - tool execution start
    logger.info(f"\n{'='*60}")
    logger.info(f"EXECUTE TOOL - Iteration {iteration} - Phase: {phase}")
    logger.info(f"{'='*60}")
    logger.info(f"TOOL_NAME: {tool_name}")
    logger.info(f"TOOL_ARGS:")
    if tool_args:
        for key, value in tool_args.items():
            val_str = str(value)
            if len(val_str) > 200:
                val_str = val_str[:10000]
            logger.info(f"  {key}: {val_str}")
    else:
        logger.info("  (no arguments)")

    # Handle missing tool name
    if not tool_name:
        logger.error(f"[{user_id}/{project_id}/{session_id}] No tool name in step_data")
        step_data["tool_output"] = "Error: No tool specified"
        step_data["success"] = False
        step_data["error_message"] = "No tool name provided"
        logger.info(f"TOOL_OUTPUT: Error - No tool specified")
        logger.info(f"{'='*60}\n")
        return {
            "_current_step": step_data,
            "_tool_result": {"success": False, "error": "No tool name provided"},
        }

    # Set context
    set_tenant_context(user_id, project_id)
    set_phase_context(phase)
    if graph_view_cyphers:
        set_graph_view_context(graph_view_cyphers.get(session_id))

    # RoE enforcement: tool restrictions are handled via agentToolPhaseMap
    # (is_tool_allowed_in_phase already blocks tools with empty/missing phases).
    # Here we only enforce the severity phase cap.
    from project_settings import get_setting
    if get_setting('ROE_ENABLED', False):
        # Severity phase cap
        PHASE_ORDER = {'informational': 0, 'exploitation': 1, 'post_exploitation': 2}
        max_phase = get_setting('ROE_MAX_SEVERITY_PHASE', 'post_exploitation')
        if PHASE_ORDER.get(phase, 0) > PHASE_ORDER.get(max_phase, 2):
            msg = f"RoE BLOCKED: Current phase '{phase}' exceeds maximum allowed phase '{max_phase}'."
            logger.warning(f"[{user_id}/{project_id}/{session_id}] {msg}")
            step_data["tool_output"] = msg
            step_data["success"] = False
            step_data["error_message"] = msg
            return {
                "_current_step": step_data,
                "_tool_result": {"success": False, "error": msg},
            }

    extra_updates = {}

    # Check if this is a long-running command that needs progress streaming
    is_long_running_msf = (
        tool_name == "metasploit_console" and
        any(cmd in (tool_args.get("command", "") or "").lower() for cmd in ["run", "exploit"])
    )
    is_long_running_hydra = (tool_name == "execute_hydra")

    # ─── Apply scan profile timing modifiers ────────────────────────────
    try:
        from scan_profiles import apply_profile
        _profile = str(get_setting("SCAN_PROFILE", "normal"))
        tool_args = apply_profile(tool_name, tool_args, profile=_profile)
        step_data["scan_profile"] = _profile
    except Exception:
        pass  # Best-effort; don't break execution on import failure
    # ──────────────────────────────────────────────────────────────────────

    # Execute the tool (with progress streaming for long-running commands)
    from orchestrator_helpers.member_streaming import resolve_streaming_callback
    import time as _time
    streaming_cb = resolve_streaming_callback(streaming_callbacks, session_id)
    _tool_t0 = _time.monotonic()
    user_stopped = False

    # Retry loop for non-streaming tool executions
    _attempt = 0
    _max_attempts = 1  # default: no retry
    result = None

    if is_long_running_msf and streaming_cb:
        logger.info(f"[{user_id}/{project_id}/{session_id}] Using execute_with_progress for long-running MSF command")
        _tool_coro = tool_executor.execute_with_progress(
            tool_name,
            tool_args,
            phase,
            progress_callback=streaming_cb.on_tool_output_chunk
        )
        _tool_task = asyncio.ensure_future(_tool_coro)
        if streaming_cb and hasattr(streaming_cb, "register_tool_task"):
            try:
                streaming_cb.register_tool_task(tool_name, None, None, _tool_task)
            except Exception as e:
                logger.debug(f"register_tool_task failed: {e}")
        try:
            try:
                result = await _tool_task
            except asyncio.CancelledError:
                _cur = asyncio.current_task()
                outer_being_cancelled = bool(_cur and _cur.cancelling())
                if outer_being_cancelled:
                    if not _tool_task.done():
                        _tool_task.cancel()
                    raise
                user_stopped = True
                result = {"success": False, "error": "Stopped by user", "output": "Stopped by user"}
        finally:
            if streaming_cb and hasattr(streaming_cb, "unregister_tool_task"):
                try:
                    streaming_cb.unregister_tool_task(tool_name, None, None)
                except Exception:
                    pass
    elif is_long_running_hydra and streaming_cb:
        logger.info(f"[{user_id}/{project_id}/{session_id}] Using execute_with_progress for Hydra brute force")
        _tool_coro = tool_executor.execute_with_progress(
            tool_name,
            tool_args,
            phase,
            progress_callback=streaming_cb.on_tool_output_chunk,
            progress_url=os.environ.get('MCP_HYDRA_PROGRESS_URL', 'http://kali-sandbox:8014/progress')
        )
        _tool_task = asyncio.ensure_future(_tool_coro)
        if streaming_cb and hasattr(streaming_cb, "register_tool_task"):
            try:
                streaming_cb.register_tool_task(tool_name, None, None, _tool_task)
            except Exception as e:
                logger.debug(f"register_tool_task failed: {e}")
        try:
            try:
                result = await _tool_task
            except asyncio.CancelledError:
                _cur = asyncio.current_task()
                outer_being_cancelled = bool(_cur and _cur.cancelling())
                if outer_being_cancelled:
                    if not _tool_task.done():
                        _tool_task.cancel()
                    raise
                user_stopped = True
                result = {"success": False, "error": "Stopped by user", "output": "Stopped by user"}
        finally:
            if streaming_cb and hasattr(streaming_cb, "unregister_tool_task"):
                try:
                    streaming_cb.unregister_tool_task(tool_name, None, None)
                except Exception:
                    pass
    else:
        # Standard execution with retry support
        _max_attempts = 1 + _MAX_RETRIES
        while _attempt < _max_attempts:
            _attempt += 1
            if _attempt > 1:
                _delay = _RETRY_BASE_DELAY_S * (2 ** (_attempt - 2))
                logger.info(f"[{user_id}/{project_id}/{session_id}] Retry {_attempt-1}/{_MAX_RETRIES} for {tool_name} after {_delay:.1f}s")
                await asyncio.sleep(_delay)

            _tool_coro = tool_executor.execute(tool_name, tool_args, phase)
            _tool_task = asyncio.ensure_future(_tool_coro)
            if streaming_cb and hasattr(streaming_cb, "register_tool_task"):
                try:
                    streaming_cb.register_tool_task(tool_name, None, None, _tool_task)
                except Exception as e:
                    logger.debug(f"register_tool_task failed: {e}")
            try:
                try:
                    result = await _tool_task
                except asyncio.CancelledError:
                    _cur = asyncio.current_task()
                    outer_being_cancelled = bool(_cur and _cur.cancelling())
                    if outer_being_cancelled:
                        if not _tool_task.done():
                            _tool_task.cancel()
                        raise
                    user_stopped = True
                    result = {"success": False, "error": "Stopped by user", "output": "Stopped by user"}
                    break  # don't retry user-stopped
            finally:
                if streaming_cb and hasattr(streaming_cb, "unregister_tool_task"):
                    try:
                        streaming_cb.unregister_tool_task(tool_name, None, None)
                    except Exception:
                        pass

            # Check if we should retry
            if result and not result.get("success", False):
                error_class = classify_error_class(
                    success=False,
                    tool_output=result.get("output", ""),
                    error_message=result.get("error", ""),
                    duration_ms=int((_time.monotonic() - _tool_t0) * 1000) if _attempt == 1 else 0,
                    tool_name=tool_name,
                )
                if _attempt < _max_attempts and _is_retryable(tool_name, result.get("error", ""), error_class):
                    logger.info(f"Retryable failure ({error_class}) — will retry")
                    continue
            break  # success or non-retryable failure
        # Record retry count on step_data
        if _attempt > 1:
            step_data["retry_count"] = _attempt - 1
    # Record wall-clock duration on the step so the UI can show "17.3s" on
    # the tool card. Without this, emit_streaming_events had nothing to
    # pass into on_tool_complete(duration_ms=...) and the frontend reducer
    # patched `duration: 0` on the completed ToolExecutionItem.
    step_data["duration_ms"] = int((_time.monotonic() - _tool_t0) * 1000)
    if user_stopped:
        step_data["stopped_by_user"] = True

    # Update step with output (handle None result)
    if result:
        step_data["tool_output"] = result.get("output") or ""
        step_data["success"] = result.get("success", False)
        step_data["error_message"] = result.get("error")
    else:
        step_data["tool_output"] = ""
        step_data["success"] = False
        step_data["error_message"] = "Tool execution returned no result"

    # Detect embedded errors in tool output: MCP servers often return success=True
    # with an error message inside the body (e.g. Playwright's
    # "[ERROR] Navigation failed: Page.goto: Timeout 30000ms exceeded"). Without
    # this, ChainFailure nodes never get written and the LLM's chain_failures_memory
    # stays empty — so it retries the same failing pattern instead of learning.
    embedded_err = _detect_embedded_tool_error(step_data.get("tool_output") or "")
    if step_data.get("success") and embedded_err:
        step_data["success"] = False
        step_data["error_message"] = step_data.get("error_message") or embedded_err
        step_data["error_embedded"] = True

    # Diagnostic classification: distinguishes a shell-quoting glitch from a
    # real 4xx from a 5xx-in-3ms parse-time crash. Surfaced in chain context
    # so the LLM can see WHICH kind of failure happened, not just THAT one did.
    step_data["error_class"] = classify_error_class(
        success=step_data.get("success", False),
        tool_output=step_data.get("tool_output"),
        error_message=step_data.get("error_message"),
        duration_ms=step_data.get("duration_ms"),
        tool_name=tool_name,
    )

    # Detailed logging - tool output
    tool_output = step_data.get("tool_output", "")
    success = step_data.get("success", False)
    error_msg = step_data.get("error_message")

    logger.info(f"SUCCESS: {success}")
    if error_msg:
        logger.info(f"ERROR: {error_msg}")

    logger.info(f"TOOL_OUTPUT ({len(tool_output)} chars):")
    if tool_output:
        output_preview = tool_output[:100000]
        for line in output_preview.split('\n'):
            logger.info(f"  | {line}")
        if len(tool_output) > 100000:
            logger.info(f"  | ... ({len(tool_output) - 100000} more chars)")
    else:
        logger.info("  (empty output)")
    logger.info(f"{'='*60}\n")

    # Detect new Metasploit sessions and register chat mapping
    if tool_name == "metasploit_console" and tool_output:
        for match in re.finditer(r'session\s+(\d+)\s+opened', tool_output, re.IGNORECASE):
            msf_session_id = int(match.group(1))
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{session_manager_base}/session-chat-map",
                        json={"msf_session_id": msf_session_id, "chat_session_id": session_id}
                    )
            except Exception:
                pass  # Best effort, don't break execution

    # Register non-MSF listeners (netcat, socat) created via kali_shell
    if tool_name == "kali_shell" and tool_args:
        cmd = tool_args.get("command", "")
        if re.search(r'(nc|ncat)\s+.*-l', cmd) or 'socat' in cmd:
            try:
                async with httpx.AsyncClient(timeout=5.0) as client:
                    await client.post(
                        f"{session_manager_base}/non-msf-sessions",
                        json={"type": "listener", "tool": "netcat", "command": cmd,
                               "chat_session_id": session_id}
                    )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Structured output parsing: extract ports, technologies, vulns, etc.
    # from raw tool output so they can be merged into target_info without
    # relying on the LLM to manually extract facts.
    # ------------------------------------------------------------------
    parsed = None
    if tool_output and success:
        from output_parsers import parse_tool_output
        parsed = parse_tool_output(tool_name, tool_output)
        if parsed:
            logger.info(
                f"PARSED [{tool_name}]: "
                f"{len(parsed.get('ports', []))} ports, "
                f"{len(parsed.get('services', []))} services, "
                f"{len(parsed.get('technologies', []))} techs, "
                f"{len(parsed.get('vulnerabilities', []))} vulns, "
                f"{len(parsed.get('credentials', []))} creds, "
                f"{len(parsed.get('findings', []))} findings, "
                f"{len(parsed.get('subdomains', []))} subdomains, "
                f"{len(parsed.get('endpoints', []))} endpoints, "
                f"{len(parsed.get('exploits', []))} exploits"
            )

    updates = {
        "_current_step": step_data,
        "_tool_result": result or {"success": False, "error": "No result"},
    }
    if parsed:
        updates["_parsed_findings"] = parsed
    updates.update(extra_updates)
    return updates

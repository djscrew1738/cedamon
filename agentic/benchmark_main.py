#!/usr/bin/env python3
"""
RedaMon XBOW Benchmark Runner — Standalone Entry Point.

Runs RedaMon in autonomous benchmark mode against CTF-style challenge files.

Usage:
    python -m agentic.benchmark_main --task /path/to/task.json

Task JSON format:
    {
        "task_id": "htb-sherlock-001",
        "objective": "Find the flag on machine 10.10.10.5",
        "target": "10.10.10.5",
        "flag_format": "HTB\\\\{[^}]+\\\\}",
        "hints": ["optional hint 1"],
        "category": "puzzle",
        "timeout_minutes": 60
    }

Environment variables:
    REDAMON_BENCHMARK_DIR — Output directory for benchmark results
                             (default: /tmp/redamon_benchmark)
    REDAMON_CONTEXT_DB     — Path to context manager's SQLite database
                             (default: /tmp/redamon_context.db)
    REDAMON_OODA_LOG_DIR   — Directory for OODA audit logs
                             (default: /tmp/redamon_ooda_logs)
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

# Add agentic directory to path for imports.
_AGENTIC_DIR = Path(__file__).resolve().parent
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(
            os.environ.get(
                "REDAMON_BENCHMARK_LOG",
                "/tmp/redamon_benchmark.log",
            )
        ),
    ],
)
logger = logging.getLogger("redamon.benchmark")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def main() -> int:
    """Main entry point for benchmark mode."""
    parser = argparse.ArgumentParser(
        description="RedaMon XBOW Benchmark Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--task",
        required=True,
        help="Path to benchmark task JSON file",
    )
    parser.add_argument(
        "--ooda",
        action="store_true",
        default=False,
        help="Use OODA loop (default: use standard ReAct graph)",
    )
    parser.add_argument(
        "--max-cycles",
        type=int,
        default=200,
        help="Maximum OODA cycles (default: 200)",
    )
    parser.add_argument(
        "--output-dir",
        default=os.environ.get(
            "REDAMON_BENCHMARK_DIR", "/tmp/redamon_benchmark"
        ),
        help="Output directory for benchmark results",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        default=False,
        help="Enable debug logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate task file.
    task_path = Path(args.task)
    if not task_path.exists():
        logger.error("Task file not found: %s", task_path)
        return 1

    # Create output directory.
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load and display task.
    try:
        with open(task_path, "r", encoding="utf-8") as f:
            task = json.load(f)
    except Exception as exc:
        logger.error("Failed to load task file: %s", exc)
        return 1

    logger.info("=" * 70)
    logger.info("  RedaMon XBOW Benchmark Runner")
    logger.info("=" * 70)
    logger.info("  Task ID:    %s", task.get("task_id", "unknown"))
    logger.info("  Objective:  %s", task.get("objective", "")[:100])
    logger.info("  Target:     %s", task.get("target", ""))
    logger.info("  Flag fmt:   %s", task.get("flag_format", "FLAG{...}"))
    logger.info("  Category:   %s", task.get("category", "puzzle"))
    logger.info("  Timeout:    %d min", task.get("timeout_minutes", 60))
    logger.info("  OODA mode:  %s", "enabled" if args.ooda else "disabled")
    logger.info("  Output dir: %s", output_dir)
    logger.info("=" * 70)

    # ------------------------------------------------------------------
    # Initialize the orchestrator.
    # ------------------------------------------------------------------
    logger.info("Initializing AgentOrchestrator...")

    from orchestrator import AgentOrchestrator

    orchestrator = AgentOrchestrator()

    # Set environment variables for the orchestrator if not already set.
    if not os.environ.get("OPENAI_MODEL"):
        os.environ["OPENAI_MODEL"] = os.environ.get(
            "REDAMON_MODEL", "deepseek/deepseek-v4-pro"
        )

    try:
        await orchestrator.initialize()
    except Exception as exc:
        logger.error("Orchestrator initialization failed: %s", exc)
        logger.error(
            "Make sure required services are running (Docker, Neo4j, MCP servers)."
        )
        return 1

    # ------------------------------------------------------------------
    # Run the benchmark.
    # ------------------------------------------------------------------
    start_time = time.time()

    if args.ooda:
        # Use OODA loop via the orchestrator's benchmark runner.
        logger.info("Running in OODA benchmark mode...")
        result = await orchestrator.run_benchmark(str(task_path))
    else:
        # Use standard ReAct graph via invoke.
        logger.info("Running in standard ReAct mode...")
        task_id = task.get("task_id", f"benchmark-{int(time.time())}")
        objective = task.get("objective", "Find the flag")
        target = task.get("target", "")

        # Build the question.
        question = objective
        if target and target not in question:
            question += f" Target: {target}"

        try:
            response = await orchestrator.invoke(
                question=question,
                user_id="benchmark",
                project_id=f"bench-{task_id}",
                session_id=f"bench-session-{task_id}",
            )
            result = {
                "task_id": task_id,
                "objective": objective,
                "success": response.task_complete,
                "error": response.error,
                "answer": response.answer,
                "elapsed_seconds": time.time() - start_time,
                "iterations": response.iteration_count,
            }
        except Exception as exc:
            logger.error("Invoke failed: %s", exc, exc_info=True)
            result = {
                "task_id": task_id,
                "objective": objective,
                "error": str(exc),
                "success": False,
                "elapsed_seconds": time.time() - start_time,
            }

    elapsed = time.time() - start_time

    # ------------------------------------------------------------------
    # Write results.
    # ------------------------------------------------------------------
    result_file = output_dir / f"{task.get('task_id', 'benchmark')}_result.json"
    with open(result_file, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, default=str)

    logger.info("=" * 70)
    logger.info("  BENCHMARK COMPLETE")
    logger.info("=" * 70)
    logger.info("  Task:      %s", task.get("task_id", "unknown"))
    logger.info("  Success:   %s", result.get("success", False))
    logger.info("  Elapsed:   %.1fs", elapsed)
    logger.info("  Result:    %s", result_file)
    logger.info("=" * 70)

    # Print result to stdout for pipeline consumption.
    print(json.dumps(result, indent=2, default=str))

    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

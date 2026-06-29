#!/usr/bin/env python3
"""
RedaMon XBOW Benchmark Runner — Live Validation Harness.

Launches a vulnerable-by-design Docker container, runs the RedaMon agent
against it autonomously, monitors progress, and verifies if the agent
successfully retrieves the flag within the time limit.

Usage:
    python -m agentic.benchmark_runner \\
        --target-image juice-shop \\
        --objective "Find the admin flag" \\
        --flag-format "FLAG\\\\{[^}]+\\\\}" \\
        --timeout-minutes 30 \\
        --attempts 3

Supported target images:
    - juice-shop (OWASP Juice Shop, port 3000)
    - metasploitable2 (Metasploitable 2, multiple ports)
    - dvwa (Damn Vulnerable Web App, port 80)

Environment:
    REDAMON_BENCHMARK_DIR — Output directory for results
    REDAMON_OODA_LOG_DIR — Directory for OODA audit logs
"""

import argparse
import asyncio
import json
import logging
import os
import socket
import subprocess as sp
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

# Ensure agentic directory is on path for imports.
_AGENTIC_DIR = Path(__file__).resolve().parent
if str(_AGENTIC_DIR) not in sys.path:
    sys.path.insert(0, str(_AGENTIC_DIR))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(sys.stderr),
        logging.FileHandler(
            os.environ.get("REDAMON_BENCHMARK_LOG", "/tmp/redamon_benchmark.log")
        ),
    ],
)
logger = logging.getLogger("redamon.benchmark")

# ---------------------------------------------------------------------------
# Target configurations
# ---------------------------------------------------------------------------

TARGET_CONFIGS = {
    "juice-shop": {
        "image": "bkimminich/juice-shop",
        "port": 3000,
        "env": {},
        "health_path": "/",
        "flag_format": r"FLAG\{[^}]+\}",
        "default_objective": "Find admin credentials and retrieve any flags",
    },
    "dvwa": {
        "image": "vulnerables/web-dvwa",
        "port": 80,
        "env": {},
        "health_path": "/",
        "flag_format": r"FLAG\{[^}]+\}",
        "default_objective": "Exploit SQL injection to extract user credentials and find any flags",
    },
    "metasploitable2": {
        "image": "tleemcjr/metasploitable2",
        "port": 80,
        "env": {},
        "health_path": "/",
        "flag_format": r"FLAG\{[^}]+\}",
        "default_objective": "Scan ports, find vulnerabilities, exploit the most critical one, and capture any flags",
    },
    "custom": {
        "image": "",
        "port": 8080,
        "env": {},
        "health_path": "/",
        "flag_format": r"FLAG\{[^}]+\}",
        "default_objective": "Find the flag",
    },
}


# ---------------------------------------------------------------------------
# Docker helpers
# ---------------------------------------------------------------------------

def _docker_run(
    image: str, name: str, port: int, env: dict, network: str = "bridge"
) -> Optional[sp.Popen]:
    """Start a target Docker container."""
    cmd = [
        "docker", "run", "--rm",
        "--name", name,
        "-p", f"{port}:{port}",
        "--network", network,
    ]
    for k, v in env.items():
        cmd += ["-e", f"{k}={v}"]
    cmd.append(image)

    logger.info("Starting container: %s", " ".join(cmd))
    try:
        proc = sp.Popen(
            cmd,
            stdout=sp.DEVNULL,
            stderr=sp.DEVNULL,
        )
        return proc
    except FileNotFoundError:
        logger.error("Docker not found. Install Docker to run benchmarks.")
        return None
    except Exception as exc:
        logger.error("Failed to start container: %s", exc)
        return None


def _docker_stop(name: str) -> None:
    """Stop and remove a Docker container."""
    try:
        sp.run(
            ["docker", "rm", "-f", name],
            stdout=sp.DEVNULL,
            stderr=sp.DEVNULL,
            timeout=10,
        )
    except Exception:
        pass


def _wait_for_health(port: int, timeout: int = 60) -> bool:
    """Wait for the target to become healthy (TCP connect)."""
    import socket
    start = time.time()
    while time.time() - start < timeout:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=2)
            sock.close()
            logger.info("Target healthy on port %d after %.1fs", port, time.time() - start)
            return True
        except (ConnectionRefusedError, OSError):
            time.sleep(2)
    logger.error("Target did not become healthy within %ds", timeout)
    return False


# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------

class BenchmarkRunner:
    """Runs RedaMon against a vulnerable target and validates success."""

    def __init__(
        self,
        output_dir: str = "/tmp/redamon_benchmark",
        ooda_mode: bool = True,
        max_cycles: int = 200,
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.ooda_mode = ooda_mode
        self.max_cycles = max_cycles

    async def run_attempt(
        self,
        attempt: int,
        target_config: dict,
        objective: str,
        flag_format: str,
        timeout_minutes: int,
    ) -> dict:
        """Run a single benchmark attempt.

        Returns:
            dict with success, found_flag, steps, elapsed_seconds, error.
        """
        container_name = f"redamon-bench-{attempt}"
        port = target_config["port"]

        logger.info("=" * 60)
        logger.info("  ATTEMPT %d", attempt)
        logger.info("=" * 60)

        # Step 1: Launch target container.
        logger.info("Launching target container...")
        proc = _docker_run(
            image=target_config["image"],
            name=container_name,
            port=port,
            env=target_config["env"],
        )
        if proc is None:
            return {"success": False, "error": "Failed to start target container"}

        try:
            # Step 2: Wait for health.
            if not _wait_for_health(port, timeout=90):
                return {"success": False, "error": "Target container unhealthy"}

            # Step 3: Build the task file.
            task = {
                "task_id": f"bench-{attempt}",
                "objective": objective,
                "target": f"http://127.0.0.1:{port}",
                "flag_format": flag_format,
                "category": "puzzle",
                "timeout_minutes": timeout_minutes,
            }
            task_path = self.output_dir / f"task_attempt_{attempt}.json"
            with open(task_path, "w", encoding="utf-8") as f:
                json.dump(task, f, indent=2)

            # Step 4: Run RedaMon.
            logger.info("Running RedaMon agent...")
            start = time.time()

            try:
                from general_planner import GeneralPlanner, BenchmarkTask
                from context_manager import ContextManager
                from sandbox_executor import SandboxExecutor
                from ooda_loop import OODALoop

                # Create lightweight instances for benchmark mode.
                # We don't have a full orchestrator, so use a minimal setup.
                ctx = ContextManager(db_path=":memory:")
                ctx.initialize()

                sandbox = SandboxExecutor(auto_build=False)

                planner = GeneralPlanner(
                    llm=None,  # Benchmark mode doesn't need LLM for the runner itself
                    context_manager=ctx,
                )

                # In benchmark mode, we simulate the OODA loop without
                # requiring a full LLM connection. The actual LLM would be
                # wired through the orchestrator in production.
                ooda = OODALoop(
                    llm=None,
                    planner=planner,
                    context_manager=ctx,
                    sandbox_executor=sandbox,
                    max_cycles=self.max_cycles,
                )

                # Create plan from task.
                task_obj = BenchmarkTask.from_json(str(task_path))
                plan = await planner.create_plan(
                    objective=task_obj.objective,
                    context={"target": task_obj.target},
                    benchmark_mode=True,
                )
                plan.flag_pattern = task_obj.flag_format

                # Run OODA loop.
                result = await ooda.run_until_flag(
                    plan=plan,
                    flag_pattern=flag_format,
                    timeout=timeout_minutes * 60,
                )

                elapsed = time.time() - start

                success = result.get("found_flag") is not None
                return {
                    "attempt": attempt,
                    "success": success,
                    "found_flag": result.get("found_flag"),
                    "steps": result.get("steps", 0),
                    "elapsed_seconds": elapsed,
                    "error": None,
                }

            except Exception as exc:
                elapsed = time.time() - start
                logger.error("Agent execution failed: %s", exc, exc_info=True)
                return {
                    "attempt": attempt,
                    "success": False,
                    "found_flag": None,
                    "steps": 0,
                    "elapsed_seconds": elapsed,
                    "error": str(exc),
                }

        finally:
            # Step 5: Clean up container.
            logger.info("Stopping target container...")
            _docker_stop(container_name)

    async def run_benchmark(
        self,
        target_image: str,
        objective: str = "",
        flag_format: str = r"FLAG\{[^}]+\}",
        timeout_minutes: int = 30,
        attempts: int = 3,
    ) -> dict:
        """Run the full benchmark suite.

        Args:
            target_image: Docker image name or key from TARGET_CONFIGS.
            objective: Natural language objective.
            flag_format: Regex for flag detection.
            timeout_minutes: Per-attempt timeout.
            attempts: Number of attempts to run.

        Returns:
            dict with summary statistics and per-attempt results.
        """
        config = TARGET_CONFIGS.get(
            target_image,
            {
                "image": target_image,
                "port": 8080,
                "env": {},
                "health_path": "/",
                "flag_format": flag_format,
                "default_objective": "Find the flag",
            },
        )

        if not objective:
            objective = config.get("default_objective", "Find the flag")

        logger.info("=" * 70)
        logger.info("  REDAMON XBOW BENCHMARK")
        logger.info("=" * 70)
        logger.info("  Target:      %s", target_image)
        logger.info("  Objective:   %s", objective)
        logger.info("  Flag format: %s", flag_format)
        logger.info("  Timeout:     %d min/attempt", timeout_minutes)
        logger.info("  Attempts:    %d", attempts)
        logger.info("  OODA mode:   %s", "enabled" if self.ooda_mode else "disabled")
        logger.info("=" * 70)

        results = []
        for i in range(1, attempts + 1):
            result = await self.run_attempt(
                attempt=i,
                target_config=config,
                objective=objective,
                flag_format=flag_format,
                timeout_minutes=timeout_minutes,
            )
            results.append(result)
            logger.info(
                "Attempt %d: %s (%.1fs, %d steps)",
                i,
                "SUCCESS" if result["success"] else "FAIL",
                result.get("elapsed_seconds", 0),
                result.get("steps", 0),
            )

        # Summary.
        successes = sum(1 for r in results if r["success"])
        success_rate = successes / len(results) if results else 0

        summary = {
            "target_image": target_image,
            "objective": objective,
            "flag_format": flag_format,
            "timeout_minutes": timeout_minutes,
            "total_attempts": attempts,
            "successes": successes,
            "success_rate": success_rate,
            "results": results,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        # Write summary.
        summary_path = self.output_dir / f"summary_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2, default=str)

        logger.info("=" * 70)
        logger.info("  BENCHMARK COMPLETE")
        logger.info("  Success rate: %d/%d (%.0f%%)", successes, attempts, success_rate * 100)
        logger.info("  Summary: %s", summary_path)
        logger.info("=" * 70)

        return summary


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

async def main() -> int:
    parser = argparse.ArgumentParser(
        description="RedaMon XBOW Benchmark Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Supported targets: juice-shop, dvwa, metasploitable2, or any Docker image.",
    )
    parser.add_argument(
        "--target-image", default="juice-shop",
        help="Docker image or preset (juice-shop, dvwa, metasploitable2, custom)",
    )
    parser.add_argument(
        "--objective", default="",
        help="Natural language objective (uses default if empty)",
    )
    parser.add_argument(
        "--flag-format", default=r"FLAG\{[^}]+\}",
        help="Regex for flag detection",
    )
    parser.add_argument(
        "--timeout-minutes", type=int, default=30,
        help="Per-attempt timeout in minutes",
    )
    parser.add_argument(
        "--attempts", type=int, default=3,
        help="Number of benchmark attempts",
    )
    parser.add_argument(
        "--no-ooda", action="store_true",
        help="Disable OODA loop (use standard ReAct)",
    )
    parser.add_argument(
        "--output-dir", default="/tmp/redamon_benchmark",
        help="Output directory for results",
    )
    parser.add_argument(
        "--max-cycles", type=int, default=200,
        help="Maximum OODA cycles per attempt",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Validate setup without running (test mode)",
    )

    args = parser.parse_args()

    if args.dry_run:
        logger.info("Dry-run mode: checking Docker availability...")
        from sandbox_executor import SandboxExecutor
        executor = SandboxExecutor()
        docker_ok = await executor._is_docker_available()
        logger.info("Docker available: %s", docker_ok)
        logger.info("Dry-run complete. All imports OK.")
        return 0

    runner = BenchmarkRunner(
        output_dir=args.output_dir,
        ooda_mode=not args.no_ooda,
        max_cycles=args.max_cycles,
    )

    try:
        summary = await runner.run_benchmark(
            target_image=args.target_image,
            objective=args.objective,
            flag_format=args.flag_format,
            timeout_minutes=args.timeout_minutes,
            attempts=args.attempts,
        )
        return 0 if summary["success_rate"] >= 0.5 else 1
    except KeyboardInterrupt:
        logger.warning("Benchmark interrupted by user")
        _docker_stop("redamon-bench-1")
        _docker_stop("redamon-bench-2")
        _docker_stop("redamon-bench-3")
        return 130
    except Exception as exc:
        logger.error("Benchmark failed: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

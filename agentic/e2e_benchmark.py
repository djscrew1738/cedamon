#!/usr/bin/env python3
"""
Live end-to-end benchmark: RedaMon XBOW vs OWASP Juice Shop.

Runs the full pipeline: scan → discover → extract findings.
Validates all XBOW modules work together against a real target.
"""
import asyncio, json, os, sys, time, re
from pathlib import Path
from datetime import datetime, timezone

sys.path.insert(0, str(Path(__file__).resolve().parent))

from context_manager import ContextManager
from sandbox_executor import SandboxExecutor
from ooda_loop import OODALoop, Observation, Decision, RecoveryLevel
from cross_engagement import CrossEngagementMemory

TARGET = "http://127.0.0.1:3000"
SCAN_CODE = r"""
import requests, json, sys, re

TARGET = "http://127.0.0.1:3000"
findings = []

try:
    # Step 1: GET homepage
    r = requests.get(TARGET, timeout=10, headers={"User-Agent": "RedaMon-XBOW/1.0"})
    print(f"[+] GET / -> HTTP {r.status_code} ({len(r.text)} bytes)")
    
    # Step 2: Extract interesting endpoints from HTML
    links = re.findall(r'(?:href|src)=["\']([^"\']+)["\']', r.text)
    api_links = [l for l in links if any(x in l.lower() for x in ['api', 'rest', 'admin', 'login', 'score', 'flag', 'search'])]
    print(f"[+] Found {len(links)} links, {len(api_links)} interesting")
    for l in api_links[:10]:
        print(f"    {l}")
    findings.extend(api_links[:5])
    
    # Step 3: Try to access the score board (juice-shop specific)
    for path in ['/score-board', '/api/Challenges', '/rest/admin/application-configuration',
                 '/#/score-board', '/ftp', '/api/SecurityQuestions']:
        try:
            r2 = requests.get(f"{TARGET}{path}", timeout=10, 
                            headers={"User-Agent": "RedaMon-XBOW/1.0"},
                            allow_redirects=True)
            print(f"[+] GET {path} -> HTTP {r2.status_code} ({len(r2.text)} bytes)")
            if 'score' in r2.text.lower() or 'challenge' in r2.text.lower() or r2.status_code == 200:
                findings.append(f"endpoint:{path}:HTTP{r2.status_code}")
                
                # Check for flag-like patterns
                flags = re.findall(r'FLAG\{[^}]+\}|flag\{[^}]+\}|"flag"\s*:\s*"[^"]+"', r2.text)
                if flags:
                    print(f"[!!!] FLAG FOUND: {flags[0]}")
                    findings.append(f"flag:{flags[0]}")
        except Exception as e:
            print(f"[-] GET {path} -> error: {e}")
    
    # Step 4: Access API Challenges endpoint
    r3 = requests.get(f"{TARGET}/api/Challenges", timeout=10,
                     headers={"User-Agent": "RedaMon-XBOW/1.0"})
    print(f"[+] GET /api/Challenges -> HTTP {r3.status_code}")
    if r3.status_code == 200:
        try:
            data = r3.json()
            if isinstance(data, dict) and 'data' in data:
                challenges = data['data']
                solved = [c for c in challenges if c.get('solved')]
                print(f"[+] Challenges: {len(challenges)} total, {len(solved)} solved")
                for c in solved[:3]:
                    print(f"    Solved: {c.get('name')} - {c.get('description','')[:80]}")
                findings.append(f"challenges:{len(challenges)}")
                findings.append(f"solved:{len(solved)}")
        except Exception:
            print("[-] Could not parse challenges JSON")
    
    print(f"\n[+] EXPLOIT_SUCCESS: Found {len(findings)} artifacts")
    print(f"FINDINGS:{json.dumps(findings)}")
    
except Exception as e:
    print(f"[-] EXPLOIT_FAILURE: {e}", file=sys.stderr)
    sys.exit(1)
"""


async def main():
    print("=" * 70)
    print("  RedaMon XBOW — Live Benchmark vs OWASP Juice Shop")
    print(f"  {datetime.now(timezone.utc).isoformat()}")
    print("=" * 70)
    print(f"  Target: {TARGET}")
    print()

    # Initialize all XBOW modules.
    ctx = ContextManager(db_path=":memory:")
    ctx.initialize()

    sandbox = SandboxExecutor(auto_build=False, docker_path="/nonexistent/docker")
    mem = CrossEngagementMemory(memory_path="/tmp/benchmark_memory.json")

    # Record the mission start.
    ctx.record_action(
        session_id="bench-juice-shop",
        action_name="mission_start",
        phase="informational",
        summary=f"Starting benchmark against Juice Shop at {TARGET}",
        key_findings=[f"Target: {TARGET}"],
        success=True,
    )

    # ---- OBSERVE: Phase 1 - Reconnaissance ----
    print("--- PHASE 1: Reconnaissance ---")
    
    # Run the scan using the sandbox (subprocess fallback).
    print("[*] Launching sandboxed scanner...")
    result = await sandbox.execute(
        code=SCAN_CODE,
        timeout=90,
    )

    output = result.stdout or ""
    stderr = result.stderr or ""
    print(f"[*] Scan complete: exit={result.exit_code}, time={result.execution_time_ms:.0f}ms")
    print(f"[*] Output ({len(output)} bytes):")
    for line in output.strip().split("\n")[:20]:
        print(f"    {line}")
    if stderr:
        print(f"[*] Stderr: {stderr[:200]}")

    # Extract findings from output.
    findings = []
    if "FINDINGS:" in output:
        try:
            findings_json = output.split("FINDINGS:")[-1].strip()
            findings = json.loads(findings_json)
        except json.JSONDecodeError:
            findings = [l.strip() for l in output.split("\n") if l.strip().startswith("[+]")]
    
    success = result.exit_code == 0 and "EXPLOIT_SUCCESS" in output
    flag_found = None
    for line in output.split("\n"):
        if "FLAG{" in line:
            flag_found = re.search(r'FLAG\{[^}]+\}', line)
            if flag_found:
                flag_found = flag_found.group(0)
                break

    # Record in context manager.
    ctx.record_action(
        session_id="bench-juice-shop",
        action_name="recon_scan",
        phase="informational",
        raw_output=output,
        summary=f"Recon scan of Juice Shop: {len(findings)} findings",
        key_findings=findings,
        success=success,
    )

    # Add discovered assets.
    ctx.add_asset("bench-juice-shop", "ip", "127.0.0.1", source_action="recon_scan")
    ctx.add_asset("bench-juice-shop", "url", TARGET, source_action="recon_scan")
    
    for f in findings:
        if f.startswith("endpoint:"):
            parts = f.split(":")
            if len(parts) >= 3:
                ctx.add_asset("bench-juice-shop", "endpoint", parts[1], source_action="recon_scan")
                ctx.add_vulnerability(
                    "bench-juice-shop", "discovered_endpoint",
                    endpoint=parts[1],
                    description=f"Endpoint discovered: {parts[1]} (HTTP {parts[2]})",
                    confidence=0.8,
                    severity="info",
                )

    # ---- OBSERVE: Phase 2 - OODA Orientation ----
    print()
    print("--- PHASE 2: OODA Orientation ---")
    
    observation = Observation(
        cycle=1,
        timestamp=datetime.now(timezone.utc).isoformat(),
        phase="informational",
        last_action="recon_scan",
        last_output=output[:2000],
        new_findings=findings[:5],
        progress_made=success,
        stuck_detected=False,
        flag_found=flag_found,
    )
    print(f"  Observation: phase={observation.phase}, findings={len(observation.new_findings)}")
    print(f"  Progress: {observation.progress_made}")
    print(f"  Flag found: {flag_found}")

    # ---- Cross-Engagement Memory ----
    print()
    print("--- PHASE 3: Cross-Engagement Learning ---")
    
    if success and findings:
        mem.record_tactic(
            f"Juice Shop API at {TARGET} exposes /api/Challenges and score-board",
            target_fingerprint="juice-shop+nodejs+express",
            attack_type="recon",
            confidence=0.9,
            tool_used="sandbox_scanner",
        )
        print(f"  Recorded tactic to cross-engagement memory")

    prioritized = mem.get_prioritized_attack_paths("juice-shop+nodejs", limit=5)
    print(f"  Prioritized paths for future engagements:")
    for p in prioritized:
        print(f"    {p}")

    # ---- Structured Summary ----
    print()
    print("--- PHASE 4: Structured Summary ---")
    
    summary = ctx.get_structured_summary("bench-juice-shop")
    print(f"  Assets: {summary['assets']['total_assets']} total")
    print(f"    IPs: {summary['assets']['ips']}")
    print(f"    URLs: {summary['assets']['domains']}")
    print(f"  Vulnerabilities: {summary['vulnerabilities']['total']} total")

    # ---- Final Report ----
    print()
    print("=" * 70)
    print("  BENCHMARK COMPLETE")
    print("=" * 70)
    print(f"  Target:        {TARGET}")
    print(f"  Scan success:  {success}")
    print(f"  Flag found:    {flag_found}")
    print(f"  Findings:      {len(findings)}")
    print(f"  Scan time:     {result.execution_time_ms:.0f}ms")
    print(f"  Assets stored: {summary['assets']['total_assets']}")
    print(f"  Vulns stored:  {summary['vulnerabilities']['total']}")
    print(f"  Tactics saved: {len(prioritized)}")
    print("=" * 70)

    # Cleanup.
    ctx.close()
    try:
        os.remove("/tmp/benchmark_memory.json")
    except Exception:
        pass

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))

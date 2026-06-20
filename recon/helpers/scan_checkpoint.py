"""
RedAmon - Scan Checkpoint & Resumability
=========================================
Enables long-running scans to be resumed after failures/interruptions.

Saves checkpoint state after each major phase and per-target within phases.
On restart, detects checkpoint file and resumes from last completed work.

Usage:
    checkpoint = ScanCheckpoint(project_id, output_dir)
    
    # At phase start
    if checkpoint.is_phase_complete("port_scan"):
        print("Skipping port_scan - already complete")
        cached_result = checkpoint.load_phase_result("port_scan")
    else:
        result = run_port_scan(...)
        checkpoint.complete_phase("port_scan", result)
    
    # For per-target checkpointing within a phase
    for target in targets:
        if checkpoint.is_target_complete("vuln_scan", target):
            continue
        findings = scan_target(target)
        checkpoint.complete_target("vuln_scan", target, findings)
"""

import json
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
import threading
import hashlib


class ScanCheckpoint:
    """
    Manages scan checkpoints for resumability.
    
    Checkpoint Structure:
    {
        "project_id": "abc123",
        "scan_started": "2024-01-15T10:30:00",
        "last_updated": "2024-01-15T12:45:30",
        "schema_version": 1,
        "phases": {
            "domain_discovery": {"status": "complete", "completed_at": "..."},
            "port_scan": {"status": "complete", "completed_at": "..."},
            "http_probe": {"status": "in_progress", "started_at": "..."}
        },
        "targets": {
            "http_probe": {
                "example.com": {"status": "complete", "findings_count": 5},
                "api.example.com": {"status": "complete", "findings_count": 3}
            },
            "vuln_scan": {
                "https://example.com": {"status": "complete", "findings_count": 12}
            }
        },
        "phase_results_files": {
            "domain_discovery": "checkpoint_domain_discovery.json",
            "port_scan": "checkpoint_port_scan.json"
        }
    }
    """
    
    SCHEMA_VERSION = 1
    
    # Standard recon pipeline phases in execution order
    PHASE_ORDER = [
        "domain_discovery",
        "dns_resolution",
        "port_scan",
        "nmap_scan",
        "osint_enrichment",
        "http_probe",
        "resource_enum",
        "ai_surface_recon",
        "js_recon",
        "graphql_scan",
        "vuln_scan",
        "subdomain_takeover",
        "mitre_enrichment",
    ]
    
    def __init__(self, project_id: str, output_dir: Path | str,
                 auto_save: bool = True, save_interval: int = 30):
        """
        Initialize checkpoint manager.
        
        Args:
            project_id: Unique project identifier
            output_dir: Directory to store checkpoint files
            auto_save: Whether to auto-save checkpoint periodically
            save_interval: Seconds between auto-saves (if enabled)
        """
        self.project_id = project_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.checkpoint_file = self.output_dir / f"checkpoint_{project_id}.json"
        self.results_dir = self.output_dir / "checkpoint_results"
        self.results_dir.mkdir(exist_ok=True)
        
        self._lock = threading.Lock()
        self._dirty = False
        self._auto_save = auto_save
        self._save_interval = save_interval
        self._auto_save_timer = None
        
        # Load existing checkpoint or create new
        self._state = self._load_or_create()
        
        if auto_save:
            self._start_auto_save()
    
    def _load_or_create(self) -> dict:
        """Load existing checkpoint or create new state."""
        if self.checkpoint_file.exists():
            try:
                with open(self.checkpoint_file, 'r') as f:
                    state = json.load(f)
                
                # Validate schema version
                if state.get("schema_version") != self.SCHEMA_VERSION:
                    print(f"[!][Checkpoint] Schema version mismatch, creating new checkpoint")
                    return self._create_new_state()
                
                # Validate project ID
                if state.get("project_id") != self.project_id:
                    print(f"[!][Checkpoint] Project ID mismatch, creating new checkpoint")
                    return self._create_new_state()
                
                print(f"[+][Checkpoint] Loaded existing checkpoint from {self.checkpoint_file}")
                self._print_resume_summary(state)
                return state
                
            except (json.JSONDecodeError, KeyError) as e:
                print(f"[!][Checkpoint] Failed to load checkpoint: {e}")
                # Backup corrupted file
                backup = self.checkpoint_file.with_suffix(".json.corrupted")
                shutil.move(self.checkpoint_file, backup)
                return self._create_new_state()
        
        return self._create_new_state()
    
    def _create_new_state(self) -> dict:
        """Create new checkpoint state."""
        return {
            "project_id": self.project_id,
            "scan_started": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "schema_version": self.SCHEMA_VERSION,
            "phases": {},
            "targets": {},
            "phase_results_files": {},
            "stats": {
                "total_targets_processed": 0,
                "total_findings": 0,
                "resume_count": 0,
            }
        }
    
    def _print_resume_summary(self, state: dict):
        """Print summary of checkpoint state for resume."""
        phases = state.get("phases", {})
        completed = [p for p, s in phases.items() if s.get("status") == "complete"]
        in_progress = [p for p, s in phases.items() if s.get("status") == "in_progress"]
        
        if completed:
            print(f"[+][Checkpoint] Completed phases: {', '.join(completed)}")
        if in_progress:
            print(f"[*][Checkpoint] In-progress phases: {', '.join(in_progress)}")
            for phase in in_progress:
                targets = state.get("targets", {}).get(phase, {})
                completed_targets = sum(1 for t in targets.values() 
                                       if t.get("status") == "complete")
                print(f"    - {phase}: {completed_targets}/{len(targets)} targets complete")
    
    def _save(self, force: bool = False):
        """Save checkpoint to disk."""
        with self._lock:
            if not self._dirty and not force:
                return
            
            self._state["last_updated"] = datetime.now().isoformat()
            
            # Atomic write: write to temp file then rename
            temp_file = self.checkpoint_file.with_suffix(".json.tmp")
            try:
                with open(temp_file, 'w') as f:
                    json.dump(self._state, f, indent=2, default=str)
                temp_file.rename(self.checkpoint_file)
                self._dirty = False
            except Exception as e:
                print(f"[!][Checkpoint] Failed to save: {e}")
                if temp_file.exists():
                    temp_file.unlink()
    
    def _start_auto_save(self):
        """Start periodic auto-save timer."""
        def _do_auto_save():
            self._save()
            if self._auto_save:
                self._auto_save_timer = threading.Timer(
                    self._save_interval, _do_auto_save
                )
                self._auto_save_timer.daemon = True
                self._auto_save_timer.start()
        
        self._auto_save_timer = threading.Timer(self._save_interval, _do_auto_save)
        self._auto_save_timer.daemon = True
        self._auto_save_timer.start()
    
    def stop_auto_save(self):
        """Stop the auto-save timer."""
        self._auto_save = False
        if self._auto_save_timer:
            self._auto_save_timer.cancel()
            self._auto_save_timer = None
    
    # =========================================================================
    # Phase-Level Checkpointing
    # =========================================================================
    
    def is_phase_complete(self, phase: str) -> bool:
        """Check if a phase is marked complete."""
        return self._state.get("phases", {}).get(phase, {}).get("status") == "complete"
    
    def is_phase_started(self, phase: str) -> bool:
        """Check if a phase has been started."""
        return phase in self._state.get("phases", {})
    
    def start_phase(self, phase: str):
        """Mark a phase as started."""
        with self._lock:
            if phase not in self._state["phases"]:
                self._state["phases"][phase] = {
                    "status": "in_progress",
                    "started_at": datetime.now().isoformat(),
                }
                self._dirty = True
                print(f"[*][Checkpoint] Phase started: {phase}")
    
    def complete_phase(self, phase: str, result: dict | None = None,
                       save_result: bool = True):
        """
        Mark a phase as complete and optionally save its result.
        
        Args:
            phase: Phase name
            result: Phase result data (optional)
            save_result: Whether to save result to separate file
        """
        with self._lock:
            self._state["phases"][phase] = {
                "status": "complete",
                "started_at": self._state.get("phases", {}).get(phase, {}).get(
                    "started_at", datetime.now().isoformat()
                ),
                "completed_at": datetime.now().isoformat(),
            }
            
            # Save result to separate file (large results shouldn't bloat checkpoint)
            if result is not None and save_result:
                result_file = f"checkpoint_{phase}.json"
                result_path = self.results_dir / result_file
                try:
                    with open(result_path, 'w') as f:
                        json.dump(result, f, default=str)
                    self._state["phase_results_files"][phase] = result_file
                except Exception as e:
                    print(f"[!][Checkpoint] Failed to save phase result: {e}")
            
            self._dirty = True
            print(f"[+][Checkpoint] Phase complete: {phase}")
        
        self._save(force=True)
    
    def fail_phase(self, phase: str, error: str):
        """Mark a phase as failed."""
        with self._lock:
            self._state["phases"][phase] = {
                "status": "failed",
                "started_at": self._state.get("phases", {}).get(phase, {}).get(
                    "started_at", datetime.now().isoformat()
                ),
                "failed_at": datetime.now().isoformat(),
                "error": str(error)[:500],
            }
            self._dirty = True
        self._save(force=True)
    
    def load_phase_result(self, phase: str) -> dict | None:
        """Load cached result for a completed phase."""
        result_file = self._state.get("phase_results_files", {}).get(phase)
        if not result_file:
            return None
        
        result_path = self.results_dir / result_file
        if not result_path.exists():
            return None
        
        try:
            with open(result_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[!][Checkpoint] Failed to load phase result: {e}")
            return None
    
    def get_next_incomplete_phase(self) -> str | None:
        """Get the next phase that needs to be run."""
        for phase in self.PHASE_ORDER:
            if not self.is_phase_complete(phase):
                return phase
        return None
    
    # =========================================================================
    # Target-Level Checkpointing (within a phase)
    # =========================================================================
    
    def is_target_complete(self, phase: str, target: str) -> bool:
        """Check if a specific target within a phase is complete."""
        targets = self._state.get("targets", {}).get(phase, {})
        return targets.get(target, {}).get("status") == "complete"
    
    def get_incomplete_targets(self, phase: str, all_targets: list[str]) -> list[str]:
        """Get list of targets that haven't been processed yet."""
        targets = self._state.get("targets", {}).get(phase, {})
        completed = {t for t, s in targets.items() if s.get("status") == "complete"}
        return [t for t in all_targets if t not in completed]
    
    def complete_target(self, phase: str, target: str, 
                        findings_count: int = 0, metadata: dict | None = None):
        """Mark a target as complete within a phase."""
        with self._lock:
            if phase not in self._state["targets"]:
                self._state["targets"][phase] = {}
            
            self._state["targets"][phase][target] = {
                "status": "complete",
                "completed_at": datetime.now().isoformat(),
                "findings_count": findings_count,
                **(metadata or {}),
            }
            
            self._state["stats"]["total_targets_processed"] += 1
            self._state["stats"]["total_findings"] += findings_count
            self._dirty = True
    
    def fail_target(self, phase: str, target: str, error: str):
        """Mark a target as failed within a phase."""
        with self._lock:
            if phase not in self._state["targets"]:
                self._state["targets"][phase] = {}
            
            self._state["targets"][phase][target] = {
                "status": "failed",
                "failed_at": datetime.now().isoformat(),
                "error": str(error)[:200],
            }
            self._dirty = True
    
    # =========================================================================
    # Scan Management
    # =========================================================================
    
    def can_resume(self) -> bool:
        """Check if there's a valid checkpoint to resume from."""
        return (
            self.checkpoint_file.exists() and
            len(self._state.get("phases", {})) > 0
        )
    
    def get_resume_point(self) -> dict:
        """Get information about the resume point."""
        completed_phases = [
            p for p, s in self._state.get("phases", {}).items()
            if s.get("status") == "complete"
        ]
        in_progress = [
            p for p, s in self._state.get("phases", {}).items()
            if s.get("status") == "in_progress"
        ]
        
        return {
            "can_resume": self.can_resume(),
            "completed_phases": completed_phases,
            "in_progress_phases": in_progress,
            "next_phase": self.get_next_incomplete_phase(),
            "scan_started": self._state.get("scan_started"),
            "last_updated": self._state.get("last_updated"),
            "stats": self._state.get("stats", {}),
        }
    
    def reset(self, confirm: bool = False):
        """
        Reset checkpoint (start fresh scan).
        
        Args:
            confirm: Must be True to actually reset
        """
        if not confirm:
            print("[!][Checkpoint] Reset requires confirm=True")
            return
        
        with self._lock:
            # Remove checkpoint file
            if self.checkpoint_file.exists():
                self.checkpoint_file.unlink()
            
            # Remove cached results
            if self.results_dir.exists():
                shutil.rmtree(self.results_dir)
            self.results_dir.mkdir(exist_ok=True)
            
            # Reset state
            self._state = self._create_new_state()
            self._dirty = False
            
        print("[+][Checkpoint] Reset complete - starting fresh scan")
    
    def finalize(self):
        """Finalize checkpoint - call when scan completes successfully."""
        self.stop_auto_save()
        
        with self._lock:
            self._state["scan_completed"] = datetime.now().isoformat()
            self._state["status"] = "complete"
            self._dirty = True
        
        self._save(force=True)
        print(f"[+][Checkpoint] Scan finalized: {self._state['stats']}")
    
    def get_stats(self) -> dict:
        """Get checkpoint statistics."""
        return {
            "project_id": self.project_id,
            "scan_started": self._state.get("scan_started"),
            "last_updated": self._state.get("last_updated"),
            "phases_complete": sum(
                1 for s in self._state.get("phases", {}).values()
                if s.get("status") == "complete"
            ),
            "phases_total": len(self.PHASE_ORDER),
            **self._state.get("stats", {}),
        }
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_auto_save()
        self._save(force=True)
        return False


def should_resume_scan(project_id: str, output_dir: Path | str) -> bool:
    """
    Quick check if a scan should be resumed.
    
    Usage:
        if should_resume_scan(project_id, output_dir):
            print("Resuming previous scan...")
        else:
            print("Starting fresh scan...")
    """
    checkpoint_file = Path(output_dir) / f"checkpoint_{project_id}.json"
    if not checkpoint_file.exists():
        return False
    
    try:
        with open(checkpoint_file, 'r') as f:
            state = json.load(f)
        
        # Has at least one completed phase
        phases = state.get("phases", {})
        return any(s.get("status") == "complete" for s in phases.values())
    except Exception:
        return False

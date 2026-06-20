"""
RedAmon - Scan Coverage Metrics & Gap Analysis
===============================================
Track scan completeness per target and identify gaps where scans failed,
timed out, or were skipped.

Provides visibility into:
- What percentage of targets were successfully scanned
- Which hosts timed out or errored
- Which phases completed vs failed per target
- Recommendations for follow-up scans
"""

import threading
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class ScanStatus(Enum):
    """Status of a scan operation."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    TIMEOUT = "timeout"
    ERROR = "error"
    SKIPPED = "skipped"
    PARTIAL = "partial"  # Some results but not complete


@dataclass
class TargetScanResult:
    """Scan result for a single target."""
    target: str
    phase: str
    status: ScanStatus
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    findings_count: int = 0
    error_message: str = ""
    retry_count: int = 0
    
    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "phase": self.phase,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "findings_count": self.findings_count,
            "error_message": self.error_message,
            "retry_count": self.retry_count,
        }


@dataclass
class PhaseMetrics:
    """Aggregate metrics for a scan phase."""
    phase: str
    total_targets: int = 0
    successful: int = 0
    timed_out: int = 0
    errored: int = 0
    skipped: int = 0
    partial: int = 0
    total_findings: int = 0
    total_duration_seconds: float = 0.0
    avg_duration_seconds: float = 0.0
    
    @property
    def coverage_percentage(self) -> float:
        if self.total_targets == 0:
            return 100.0
        return (self.successful / self.total_targets) * 100
    
    @property
    def failure_rate(self) -> float:
        if self.total_targets == 0:
            return 0.0
        return ((self.timed_out + self.errored) / self.total_targets) * 100
    
    def to_dict(self) -> dict:
        return {
            "phase": self.phase,
            "total_targets": self.total_targets,
            "successful": self.successful,
            "timed_out": self.timed_out,
            "errored": self.errored,
            "skipped": self.skipped,
            "partial": self.partial,
            "coverage_percentage": round(self.coverage_percentage, 2),
            "failure_rate": round(self.failure_rate, 2),
            "total_findings": self.total_findings,
            "avg_duration_seconds": round(self.avg_duration_seconds, 2),
        }


class CoverageTracker:
    """
    Track scan coverage across all targets and phases.
    
    Thread-safe for concurrent scan environments.
    
    Usage:
        tracker = CoverageTracker()
        
        # Start tracking a target
        tracker.start_target("example.com", "port_scan")
        
        # Record completion
        tracker.complete_target("example.com", "port_scan", 
                               status=ScanStatus.SUCCESS, findings=5)
        
        # Get coverage report
        report = tracker.get_coverage_report()
    """
    
    SCAN_PHASES = [
        "domain_discovery",
        "port_scan",
        "http_probe",
        "resource_enum",
        "vuln_scan",
        "js_recon",
        "graphql_scan",
        "ai_surface_recon",
    ]
    
    def __init__(self):
        self._results: dict[tuple[str, str], TargetScanResult] = {}  # (target, phase) -> result
        self._lock = threading.Lock()
        self._scan_start_time: Optional[datetime] = None
        self._scan_end_time: Optional[datetime] = None
        
    def start_scan(self):
        """Mark the beginning of a scan run."""
        with self._lock:
            self._scan_start_time = datetime.now()
            self._scan_end_time = None
    
    def end_scan(self):
        """Mark the end of a scan run."""
        with self._lock:
            self._scan_end_time = datetime.now()
    
    def register_targets(self, targets: list[str], phase: str):
        """Register targets for a phase (marks them as pending)."""
        with self._lock:
            for target in targets:
                key = (target, phase)
                if key not in self._results:
                    self._results[key] = TargetScanResult(
                        target=target,
                        phase=phase,
                        status=ScanStatus.PENDING,
                    )
    
    def start_target(self, target: str, phase: str):
        """Mark a target as in-progress for a phase."""
        with self._lock:
            key = (target, phase)
            if key not in self._results:
                self._results[key] = TargetScanResult(
                    target=target,
                    phase=phase,
                    status=ScanStatus.IN_PROGRESS,
                    started_at=datetime.now(),
                )
            else:
                self._results[key].status = ScanStatus.IN_PROGRESS
                self._results[key].started_at = datetime.now()
    
    def complete_target(
        self,
        target: str,
        phase: str,
        status: ScanStatus = ScanStatus.SUCCESS,
        findings: int = 0,
        error_message: str = "",
    ):
        """Mark a target as completed for a phase."""
        with self._lock:
            key = (target, phase)
            now = datetime.now()
            
            if key not in self._results:
                self._results[key] = TargetScanResult(
                    target=target,
                    phase=phase,
                    status=status,
                    completed_at=now,
                    findings_count=findings,
                    error_message=error_message,
                )
            else:
                result = self._results[key]
                result.status = status
                result.completed_at = now
                result.findings_count = findings
                result.error_message = error_message
                if result.started_at:
                    result.duration_seconds = (now - result.started_at).total_seconds()
    
    def record_timeout(self, target: str, phase: str, duration: float = 0):
        """Record a timeout for a target."""
        self.complete_target(
            target, phase,
            status=ScanStatus.TIMEOUT,
            error_message=f"Timed out after {duration:.1f}s",
        )
    
    def record_error(self, target: str, phase: str, error: str):
        """Record an error for a target."""
        self.complete_target(
            target, phase,
            status=ScanStatus.ERROR,
            error_message=error[:500],
        )
    
    def record_skip(self, target: str, phase: str, reason: str = ""):
        """Record that a target was skipped."""
        self.complete_target(
            target, phase,
            status=ScanStatus.SKIPPED,
            error_message=reason,
        )
    
    def increment_retry(self, target: str, phase: str):
        """Increment retry count for a target."""
        with self._lock:
            key = (target, phase)
            if key in self._results:
                self._results[key].retry_count += 1
    
    def get_phase_metrics(self, phase: str) -> PhaseMetrics:
        """Get aggregate metrics for a specific phase."""
        with self._lock:
            metrics = PhaseMetrics(phase=phase)
            durations = []
            
            for (target, p), result in self._results.items():
                if p != phase:
                    continue
                    
                metrics.total_targets += 1
                metrics.total_findings += result.findings_count
                
                if result.duration_seconds > 0:
                    durations.append(result.duration_seconds)
                
                if result.status == ScanStatus.SUCCESS:
                    metrics.successful += 1
                elif result.status == ScanStatus.TIMEOUT:
                    metrics.timed_out += 1
                elif result.status == ScanStatus.ERROR:
                    metrics.errored += 1
                elif result.status == ScanStatus.SKIPPED:
                    metrics.skipped += 1
                elif result.status == ScanStatus.PARTIAL:
                    metrics.partial += 1
            
            if durations:
                metrics.total_duration_seconds = sum(durations)
                metrics.avg_duration_seconds = sum(durations) / len(durations)
            
            return metrics
    
    def get_failed_targets(self, phase: str = None) -> list[dict]:
        """Get list of targets that failed (timeout or error)."""
        with self._lock:
            failed = []
            for (target, p), result in self._results.items():
                if phase and p != phase:
                    continue
                if result.status in (ScanStatus.TIMEOUT, ScanStatus.ERROR):
                    failed.append({
                        "target": target,
                        "phase": p,
                        "status": result.status.value,
                        "error": result.error_message,
                        "retry_count": result.retry_count,
                    })
            return failed
    
    def get_coverage_report(self) -> dict:
        """Generate comprehensive coverage report."""
        with self._lock:
            # Phase-by-phase metrics
            phase_metrics = {}
            for phase in self.SCAN_PHASES:
                metrics = self.get_phase_metrics(phase)
                if metrics.total_targets > 0:
                    phase_metrics[phase] = metrics.to_dict()
            
            # Overall statistics
            all_results = list(self._results.values())
            total_targets = len(set(r.target for r in all_results))
            total_successful = sum(1 for r in all_results if r.status == ScanStatus.SUCCESS)
            total_failed = sum(1 for r in all_results if r.status in (ScanStatus.TIMEOUT, ScanStatus.ERROR))
            total_operations = len(all_results)
            
            # Failed targets list (deduplicated)
            failed_targets = list(set(
                r.target for r in all_results
                if r.status in (ScanStatus.TIMEOUT, ScanStatus.ERROR)
            ))
            
            # Targets that failed in ALL phases they were part of
            target_phase_counts: dict[str, dict] = {}
            for r in all_results:
                if r.target not in target_phase_counts:
                    target_phase_counts[r.target] = {"total": 0, "failed": 0}
                target_phase_counts[r.target]["total"] += 1
                if r.status in (ScanStatus.TIMEOUT, ScanStatus.ERROR):
                    target_phase_counts[r.target]["failed"] += 1
            
            completely_failed = [
                t for t, counts in target_phase_counts.items()
                if counts["failed"] == counts["total"] and counts["total"] > 0
            ]
            
            # Scan duration
            scan_duration = None
            if self._scan_start_time:
                end = self._scan_end_time or datetime.now()
                scan_duration = (end - self._scan_start_time).total_seconds()
            
            # Recommendations
            recommendations = self._generate_recommendations(phase_metrics, failed_targets)
            
            return {
                "scan_summary": {
                    "started_at": self._scan_start_time.isoformat() if self._scan_start_time else None,
                    "ended_at": self._scan_end_time.isoformat() if self._scan_end_time else None,
                    "duration_seconds": scan_duration,
                    "total_unique_targets": total_targets,
                    "total_scan_operations": total_operations,
                    "successful_operations": total_successful,
                    "failed_operations": total_failed,
                    "overall_success_rate": round(
                        (total_successful / total_operations * 100) if total_operations else 100, 2
                    ),
                },
                "phase_metrics": phase_metrics,
                "failed_targets": {
                    "count": len(failed_targets),
                    "completely_failed": completely_failed,
                    "targets": failed_targets[:50],  # Limit to first 50
                },
                "recommendations": recommendations,
            }
    
    def _generate_recommendations(self, phase_metrics: dict, failed_targets: list) -> list[str]:
        """Generate actionable recommendations based on coverage data."""
        recommendations = []
        
        for phase, metrics in phase_metrics.items():
            coverage = metrics.get("coverage_percentage", 100)
            timeout_count = metrics.get("timed_out", 0)
            error_count = metrics.get("errored", 0)
            
            if coverage < 80:
                recommendations.append(
                    f"⚠️ {phase}: Only {coverage:.1f}% coverage. "
                    f"Consider re-running with increased timeouts or reduced rate limits."
                )
            
            if timeout_count > 5:
                recommendations.append(
                    f"⏱️ {phase}: {timeout_count} timeouts. "
                    f"Increase phase timeout or check network/Tor connectivity."
                )
            
            if error_count > 5:
                recommendations.append(
                    f"❌ {phase}: {error_count} errors. "
                    f"Check tool configuration and target accessibility."
                )
        
        if len(failed_targets) > 10:
            recommendations.append(
                f"🔄 {len(failed_targets)} targets had failures. "
                f"Consider running a targeted partial recon on failed hosts."
            )
        
        if not recommendations:
            recommendations.append("✅ Scan coverage looks healthy across all phases.")
        
        return recommendations
    
    def print_coverage_summary(self):
        """Print a human-readable coverage summary."""
        report = self.get_coverage_report()
        summary = report["scan_summary"]
        
        print("\n" + "=" * 70)
        print("[*] SCAN COVERAGE REPORT")
        print("=" * 70)
        
        print(f"\n📊 Overall Summary:")
        print(f"   • Total targets: {summary['total_unique_targets']}")
        print(f"   • Scan operations: {summary['total_scan_operations']}")
        print(f"   • Success rate: {summary['overall_success_rate']:.1f}%")
        if summary['duration_seconds']:
            mins = summary['duration_seconds'] / 60
            print(f"   • Duration: {mins:.1f} minutes")
        
        print(f"\n📈 Phase Coverage:")
        for phase, metrics in report["phase_metrics"].items():
            status_icon = "✅" if metrics["coverage_percentage"] >= 90 else "⚠️" if metrics["coverage_percentage"] >= 70 else "❌"
            print(f"   {status_icon} {phase}: {metrics['coverage_percentage']:.1f}% "
                  f"({metrics['successful']}/{metrics['total_targets']} targets)")
            if metrics["timed_out"] > 0:
                print(f"      └─ Timeouts: {metrics['timed_out']}")
            if metrics["errored"] > 0:
                print(f"      └─ Errors: {metrics['errored']}")
        
        failed = report["failed_targets"]
        if failed["count"] > 0:
            print(f"\n⚠️ Failed Targets ({failed['count']}):")
            for target in failed["targets"][:10]:
                print(f"   • {target}")
            if failed["count"] > 10:
                print(f"   ... and {failed['count'] - 10} more")
        
        print(f"\n💡 Recommendations:")
        for rec in report["recommendations"]:
            print(f"   {rec}")
        
        print("=" * 70 + "\n")


# Global tracker instance for convenience
_global_tracker: Optional[CoverageTracker] = None


def get_coverage_tracker() -> CoverageTracker:
    """Get or create the global coverage tracker."""
    global _global_tracker
    if _global_tracker is None:
        _global_tracker = CoverageTracker()
    return _global_tracker


def reset_coverage_tracker():
    """Reset the global coverage tracker."""
    global _global_tracker
    _global_tracker = CoverageTracker()

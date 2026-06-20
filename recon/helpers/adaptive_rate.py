"""
RedAmon - Adaptive Rate Limiting
================================
Dynamic rate limiting that responds to target health signals.

Monitors response times, error rates, and HTTP status codes to automatically
adjust scan rates. Prevents IP blocking and maintains scan quality when
targets show signs of stress.
"""

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ResponseMetric:
    """Single response measurement."""
    timestamp: float
    status_code: int
    latency_ms: float
    success: bool


@dataclass
class RateDecision:
    """Rate adjustment decision with reasoning."""
    new_rate: float
    action: str  # 'decrease', 'increase', 'hold'
    reason: str
    metrics: dict


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter that adjusts based on target response patterns.
    
    Monitors a sliding window of responses and adjusts the rate when:
    - Too many 429 (rate limit) responses → aggressive decrease
    - Too many 5xx errors → moderate decrease  
    - High latency (> threshold) → moderate decrease
    - Healthy responses → gradual increase back to baseline
    
    Thread-safe for concurrent scan environments.
    """
    
    def __init__(
        self,
        initial_rps: float,
        min_rps: float = 5.0,
        max_rps: float = 200.0,
        window_size: int = 100,
        latency_threshold_ms: float = 5000.0,
        error_threshold_pct: float = 0.15,
        rate_limit_threshold_pct: float = 0.05,
        decrease_factor: float = 0.7,
        increase_factor: float = 1.05,
        cooldown_seconds: float = 10.0,
    ):
        """
        Initialize adaptive rate limiter.
        
        Args:
            initial_rps: Starting requests per second
            min_rps: Floor rate (never go below this)
            max_rps: Ceiling rate (never exceed this)
            window_size: Number of responses to track in sliding window
            latency_threshold_ms: Latency above this triggers rate decrease
            error_threshold_pct: Error rate above this triggers decrease
            rate_limit_threshold_pct: 429 rate above this triggers aggressive decrease
            decrease_factor: Multiply rate by this when decreasing (0.7 = 30% drop)
            increase_factor: Multiply rate by this when increasing (1.05 = 5% rise)
            cooldown_seconds: Minimum time between rate adjustments
        """
        self.initial_rps = initial_rps
        self.current_rps = initial_rps
        self.min_rps = min_rps
        self.max_rps = max_rps
        self.window_size = window_size
        self.latency_threshold_ms = latency_threshold_ms
        self.error_threshold_pct = error_threshold_pct
        self.rate_limit_threshold_pct = rate_limit_threshold_pct
        self.decrease_factor = decrease_factor
        self.increase_factor = increase_factor
        self.cooldown_seconds = cooldown_seconds
        
        self._window: deque[ResponseMetric] = deque(maxlen=window_size)
        self._lock = threading.Lock()
        self._last_adjustment = 0.0
        self._adjustment_history: list[RateDecision] = []
        
    def record_response(
        self,
        status_code: int,
        latency_ms: float,
        success: bool = None,
    ) -> Optional[RateDecision]:
        """
        Record a response and potentially adjust rate.
        
        Args:
            status_code: HTTP status code (0 for connection errors)
            latency_ms: Response time in milliseconds
            success: Override success detection (default: status < 400)
            
        Returns:
            RateDecision if rate was adjusted, None otherwise
        """
        if success is None:
            success = 200 <= status_code < 400
            
        metric = ResponseMetric(
            timestamp=time.time(),
            status_code=status_code,
            latency_ms=latency_ms,
            success=success,
        )
        
        with self._lock:
            self._window.append(metric)
            
            # Only evaluate after minimum samples and cooldown
            if len(self._window) < 20:
                return None
            if time.time() - self._last_adjustment < self.cooldown_seconds:
                return None
                
            return self._evaluate_and_adjust()
    
    def _evaluate_and_adjust(self) -> Optional[RateDecision]:
        """Evaluate window metrics and adjust rate if needed. Caller holds lock."""
        metrics = self._compute_metrics()
        
        # Priority 1: Rate limiting (429s) - aggressive decrease
        if metrics['rate_limit_pct'] > self.rate_limit_threshold_pct:
            return self._decrease_rate(
                factor=0.5,  # More aggressive for 429s
                reason=f"Rate limiting detected: {metrics['rate_limit_pct']:.1%} of responses are 429",
                metrics=metrics,
            )
        
        # Priority 2: Server errors (5xx) - moderate decrease
        if metrics['error_5xx_pct'] > self.error_threshold_pct:
            return self._decrease_rate(
                factor=self.decrease_factor,
                reason=f"High 5xx error rate: {metrics['error_5xx_pct']:.1%}",
                metrics=metrics,
            )
        
        # Priority 3: High latency - moderate decrease
        if metrics['avg_latency_ms'] > self.latency_threshold_ms:
            return self._decrease_rate(
                factor=self.decrease_factor,
                reason=f"High latency: {metrics['avg_latency_ms']:.0f}ms avg (threshold: {self.latency_threshold_ms}ms)",
                metrics=metrics,
            )
        
        # Priority 4: Connection errors - moderate decrease
        if metrics['connection_error_pct'] > self.error_threshold_pct:
            return self._decrease_rate(
                factor=self.decrease_factor,
                reason=f"High connection error rate: {metrics['connection_error_pct']:.1%}",
                metrics=metrics,
            )
        
        # Healthy: gradual increase back toward initial rate
        if (metrics['success_pct'] > 0.9 and 
            metrics['avg_latency_ms'] < self.latency_threshold_ms * 0.5 and
            self.current_rps < self.initial_rps):
            return self._increase_rate(
                reason=f"Healthy responses ({metrics['success_pct']:.1%} success, {metrics['avg_latency_ms']:.0f}ms latency)",
                metrics=metrics,
            )
        
        return None
    
    def _compute_metrics(self) -> dict:
        """Compute metrics from current window. Caller holds lock."""
        if not self._window:
            return {
                'total': 0,
                'success_pct': 1.0,
                'rate_limit_pct': 0.0,
                'error_5xx_pct': 0.0,
                'connection_error_pct': 0.0,
                'avg_latency_ms': 0.0,
            }
        
        total = len(self._window)
        successes = sum(1 for m in self._window if m.success)
        rate_limits = sum(1 for m in self._window if m.status_code == 429)
        errors_5xx = sum(1 for m in self._window if 500 <= m.status_code < 600)
        conn_errors = sum(1 for m in self._window if m.status_code == 0)
        
        latencies = [m.latency_ms for m in self._window if m.latency_ms > 0]
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0
        
        return {
            'total': total,
            'success_pct': successes / total,
            'rate_limit_pct': rate_limits / total,
            'error_5xx_pct': errors_5xx / total,
            'connection_error_pct': conn_errors / total,
            'avg_latency_ms': avg_latency,
        }
    
    def _decrease_rate(self, factor: float, reason: str, metrics: dict) -> RateDecision:
        """Decrease rate by factor. Caller holds lock."""
        old_rate = self.current_rps
        self.current_rps = max(self.current_rps * factor, self.min_rps)
        self._last_adjustment = time.time()
        
        decision = RateDecision(
            new_rate=self.current_rps,
            action='decrease',
            reason=reason,
            metrics=metrics,
        )
        self._adjustment_history.append(decision)
        
        print(f"[*][AdaptiveRate] ⬇ Rate decreased: {old_rate:.1f} → {self.current_rps:.1f} rps | {reason}")
        return decision
    
    def _increase_rate(self, reason: str, metrics: dict) -> RateDecision:
        """Increase rate toward initial. Caller holds lock."""
        old_rate = self.current_rps
        self.current_rps = min(self.current_rps * self.increase_factor, self.initial_rps, self.max_rps)
        self._last_adjustment = time.time()
        
        decision = RateDecision(
            new_rate=self.current_rps,
            action='increase',
            reason=reason,
            metrics=metrics,
        )
        self._adjustment_history.append(decision)
        
        print(f"[*][AdaptiveRate] ⬆ Rate increased: {old_rate:.1f} → {self.current_rps:.1f} rps | {reason}")
        return decision
    
    def get_current_rate(self) -> float:
        """Get current rate limit (thread-safe)."""
        with self._lock:
            return self.current_rps
    
    def get_delay_seconds(self) -> float:
        """Get delay between requests based on current rate."""
        with self._lock:
            return 1.0 / self.current_rps if self.current_rps > 0 else 1.0
    
    def reset(self):
        """Reset to initial state."""
        with self._lock:
            self.current_rps = self.initial_rps
            self._window.clear()
            self._last_adjustment = 0.0
            self._adjustment_history.clear()
    
    def get_summary(self) -> dict:
        """Get summary of rate limiter state and history."""
        with self._lock:
            metrics = self._compute_metrics()
            return {
                'current_rps': self.current_rps,
                'initial_rps': self.initial_rps,
                'min_rps': self.min_rps,
                'max_rps': self.max_rps,
                'window_size': len(self._window),
                'adjustments_made': len(self._adjustment_history),
                'current_metrics': metrics,
                'last_adjustments': [
                    {'action': d.action, 'rate': d.new_rate, 'reason': d.reason}
                    for d in self._adjustment_history[-5:]
                ],
            }


class TargetHealthMonitor:
    """
    Monitor health across multiple targets with per-target rate limiting.
    
    Useful when scanning multiple hosts that may have different tolerance levels.
    """
    
    def __init__(self, default_rps: float = 50.0, **limiter_kwargs):
        self._limiters: dict[str, AdaptiveRateLimiter] = {}
        self._default_rps = default_rps
        self._limiter_kwargs = limiter_kwargs
        self._lock = threading.Lock()
    
    def get_limiter(self, target: str) -> AdaptiveRateLimiter:
        """Get or create rate limiter for a target."""
        with self._lock:
            if target not in self._limiters:
                self._limiters[target] = AdaptiveRateLimiter(
                    initial_rps=self._default_rps,
                    **self._limiter_kwargs,
                )
            return self._limiters[target]
    
    def record_response(self, target: str, status_code: int, latency_ms: float) -> Optional[RateDecision]:
        """Record response for a specific target."""
        return self.get_limiter(target).record_response(status_code, latency_ms)
    
    def get_rate(self, target: str) -> float:
        """Get current rate for a target."""
        return self.get_limiter(target).get_current_rate()
    
    def get_global_summary(self) -> dict:
        """Get summary across all targets."""
        with self._lock:
            return {
                'targets_monitored': len(self._limiters),
                'per_target': {
                    target: limiter.get_summary()
                    for target, limiter in self._limiters.items()
                },
                'lowest_rate_target': min(
                    self._limiters.items(),
                    key=lambda x: x[1].get_current_rate(),
                    default=(None, None)
                )[0] if self._limiters else None,
            }

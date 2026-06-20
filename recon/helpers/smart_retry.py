"""
RedAmon - Unified Smart Retry Decorator
========================================
Provides consistent retry behavior across all recon modules with:
- Failure classification (transient vs permanent)
- Exponential backoff with jitter
- Circuit breaker for repeated failures
- Retry statistics tracking

Usage:
    from recon.helpers import smart_retry, RetryConfig, ErrorClass
    
    @smart_retry(max_attempts=3, base_delay=1.0)
    def call_external_api(url):
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    
    # With custom error classification
    @smart_retry(
        max_attempts=5,
        permanent_errors=[401, 403, 404],
        transient_errors=[429, 500, 502, 503, 504]
    )
    def fetch_cve_data(cve_id):
        ...
"""

import functools
import random
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Any, Callable, Optional, Type
import logging

logger = logging.getLogger(__name__)


class ErrorClass(Enum):
    """Classification of errors for retry decisions."""
    TRANSIENT = auto()      # Retry: 429, 500, 502, 503, 504, timeout, connection
    PERMANENT = auto()      # No retry: 400, 401, 403, 404, invalid data
    UNKNOWN = auto()        # Retry with caution
    CIRCUIT_OPEN = auto()   # Circuit breaker tripped


@dataclass
class RetryStats:
    """Statistics for retry operations."""
    total_calls: int = 0
    successful_calls: int = 0
    failed_calls: int = 0
    total_retries: int = 0
    transient_errors: int = 0
    permanent_errors: int = 0
    circuit_breaks: int = 0
    total_delay_seconds: float = 0.0
    last_error: Optional[str] = None
    last_error_time: Optional[datetime] = None
    
    def success_rate(self) -> float:
        if self.total_calls == 0:
            return 1.0
        return self.successful_calls / self.total_calls
    
    def to_dict(self) -> dict:
        return {
            "total_calls": self.total_calls,
            "successful_calls": self.successful_calls,
            "failed_calls": self.failed_calls,
            "success_rate": f"{self.success_rate():.1%}",
            "total_retries": self.total_retries,
            "transient_errors": self.transient_errors,
            "permanent_errors": self.permanent_errors,
            "circuit_breaks": self.circuit_breaks,
            "avg_delay_per_call": f"{self.total_delay_seconds / max(1, self.total_calls):.2f}s",
            "last_error": self.last_error,
            "last_error_time": self.last_error_time.isoformat() if self.last_error_time else None,
        }


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    base_delay: float = 1.0
    max_delay: float = 60.0
    exponential_base: float = 2.0
    jitter: float = 0.1  # Random jitter factor (0-1)
    
    # Error classification
    transient_status_codes: tuple = (429, 500, 502, 503, 504)
    permanent_status_codes: tuple = (400, 401, 403, 404, 405, 410, 422)
    
    # Exception types to consider transient
    transient_exceptions: tuple = (
        TimeoutError,
        ConnectionError,
        ConnectionResetError,
        ConnectionRefusedError,
    )
    
    # Circuit breaker settings
    circuit_breaker_enabled: bool = True
    circuit_breaker_threshold: int = 5  # Failures before opening circuit
    circuit_breaker_timeout: float = 60.0  # Seconds before trying again
    
    # Logging
    log_retries: bool = True
    log_prefix: str = "[Retry]"


class CircuitBreaker:
    """
    Circuit breaker to prevent repeated calls to failing services.
    
    States:
    - CLOSED: Normal operation, requests go through
    - OPEN: Too many failures, requests fail fast
    - HALF_OPEN: Testing if service recovered
    """
    
    def __init__(self, threshold: int = 5, timeout: float = 60.0):
        self.threshold = threshold
        self.timeout = timeout
        self._failure_count = 0
        self._last_failure_time: Optional[datetime] = None
        self._state = "closed"
        self._lock = threading.Lock()
    
    def record_success(self):
        with self._lock:
            self._failure_count = 0
            self._state = "closed"
    
    def record_failure(self):
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = datetime.now()
            if self._failure_count >= self.threshold:
                self._state = "open"
    
    def can_proceed(self) -> bool:
        with self._lock:
            if self._state == "closed":
                return True
            
            if self._state == "open":
                # Check if timeout has passed
                if self._last_failure_time:
                    elapsed = (datetime.now() - self._last_failure_time).total_seconds()
                    if elapsed >= self.timeout:
                        self._state = "half_open"
                        return True
                return False
            
            # half_open: allow one request to test
            return True
    
    @property
    def is_open(self) -> bool:
        return self._state == "open"


# Global registry of circuit breakers (keyed by function name)
_circuit_breakers: dict[str, CircuitBreaker] = {}
_circuit_breakers_lock = threading.Lock()

# Global registry of retry stats
_retry_stats: dict[str, RetryStats] = {}
_retry_stats_lock = threading.Lock()


def get_circuit_breaker(name: str, config: RetryConfig) -> CircuitBreaker:
    """Get or create a circuit breaker for a function."""
    with _circuit_breakers_lock:
        if name not in _circuit_breakers:
            _circuit_breakers[name] = CircuitBreaker(
                threshold=config.circuit_breaker_threshold,
                timeout=config.circuit_breaker_timeout,
            )
        return _circuit_breakers[name]


def get_retry_stats(name: str) -> RetryStats:
    """Get retry stats for a function."""
    with _retry_stats_lock:
        if name not in _retry_stats:
            _retry_stats[name] = RetryStats()
        return _retry_stats[name]


def get_all_retry_stats() -> dict[str, dict]:
    """Get retry stats for all tracked functions."""
    with _retry_stats_lock:
        return {name: stats.to_dict() for name, stats in _retry_stats.items()}


def classify_error(exc: Exception, config: RetryConfig) -> ErrorClass:
    """Classify an exception to determine retry behavior."""
    # Check for transient exception types
    if isinstance(exc, config.transient_exceptions):
        return ErrorClass.TRANSIENT
    
    # Check requests-specific errors
    if hasattr(exc, 'response') and exc.response is not None:
        status_code = exc.response.status_code
        if status_code in config.transient_status_codes:
            return ErrorClass.TRANSIENT
        if status_code in config.permanent_status_codes:
            return ErrorClass.PERMANENT
    
    # DNS errors are transient
    exc_str = str(type(exc).__name__).lower()
    if 'dns' in exc_str or 'resolve' in exc_str or 'gaierror' in exc_str:
        return ErrorClass.TRANSIENT
    
    # SSL errors can be transient (handshake timeouts) or permanent (cert issues)
    if 'ssl' in exc_str:
        if 'timeout' in str(exc).lower() or 'connection' in str(exc).lower():
            return ErrorClass.TRANSIENT
        return ErrorClass.PERMANENT
    
    # OSError with errno can indicate transient issues
    if isinstance(exc, OSError):
        import errno
        transient_errnos = [errno.ETIMEDOUT, errno.ECONNREFUSED, errno.ECONNRESET,
                           errno.ENETUNREACH, errno.EHOSTUNREACH]
        if hasattr(exc, 'errno') and exc.errno in transient_errnos:
            return ErrorClass.TRANSIENT
    
    return ErrorClass.UNKNOWN


def calculate_delay(attempt: int, config: RetryConfig) -> float:
    """Calculate delay before next retry with exponential backoff and jitter."""
    # Exponential backoff: base_delay * (exponential_base ^ attempt)
    delay = config.base_delay * (config.exponential_base ** attempt)
    
    # Cap at max_delay
    delay = min(delay, config.max_delay)
    
    # Add jitter (random factor to prevent thundering herd)
    jitter_range = delay * config.jitter
    delay += random.uniform(-jitter_range, jitter_range)
    
    return max(0, delay)


def smart_retry(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    exponential_base: float = 2.0,
    jitter: float = 0.1,
    transient_errors: tuple | list | None = None,
    permanent_errors: tuple | list | None = None,
    transient_exceptions: tuple | None = None,
    circuit_breaker: bool = True,
    circuit_threshold: int = 5,
    circuit_timeout: float = 60.0,
    log_prefix: str = "[Retry]",
    on_retry: Callable[[Exception, int], None] | None = None,
    reraise_permanent: bool = True,
):
    """
    Decorator for smart retry with failure classification and circuit breaker.
    
    Args:
        max_attempts: Maximum number of attempts (including first try)
        base_delay: Base delay between retries in seconds
        max_delay: Maximum delay cap in seconds
        exponential_base: Base for exponential backoff (default 2.0)
        jitter: Random jitter factor (0-1)
        transient_errors: Status codes to consider transient (retry)
        permanent_errors: Status codes to consider permanent (fail fast)
        transient_exceptions: Exception types to consider transient
        circuit_breaker: Whether to use circuit breaker
        circuit_threshold: Failures before opening circuit
        circuit_timeout: Seconds before testing circuit again
        log_prefix: Prefix for log messages
        on_retry: Optional callback(exception, attempt_number) on each retry
        reraise_permanent: Whether to reraise permanent errors immediately
    
    Usage:
        @smart_retry(max_attempts=3, base_delay=1.0)
        def fetch_data(url):
            return requests.get(url, timeout=30).json()
        
        @smart_retry(transient_errors=[429, 503], permanent_errors=[401, 404])
        def call_api(endpoint):
            ...
    """
    # Build config
    config = RetryConfig(
        max_attempts=max_attempts,
        base_delay=base_delay,
        max_delay=max_delay,
        exponential_base=exponential_base,
        jitter=jitter,
        circuit_breaker_enabled=circuit_breaker,
        circuit_breaker_threshold=circuit_threshold,
        circuit_breaker_timeout=circuit_timeout,
        log_prefix=log_prefix,
    )
    
    if transient_errors:
        config.transient_status_codes = tuple(transient_errors)
    if permanent_errors:
        config.permanent_status_codes = tuple(permanent_errors)
    if transient_exceptions:
        config.transient_exceptions = transient_exceptions
    
    def decorator(func: Callable) -> Callable:
        func_name = f"{func.__module__}.{func.__qualname__}"
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            stats = get_retry_stats(func_name)
            cb = get_circuit_breaker(func_name, config) if config.circuit_breaker_enabled else None
            
            stats.total_calls += 1
            
            # Check circuit breaker
            if cb and not cb.can_proceed():
                stats.circuit_breaks += 1
                raise CircuitBreakerOpen(
                    f"{config.log_prefix} Circuit breaker open for {func_name}"
                )
            
            last_exception = None
            total_delay = 0.0
            
            for attempt in range(config.max_attempts):
                try:
                    result = func(*args, **kwargs)
                    
                    # Success
                    stats.successful_calls += 1
                    if cb:
                        cb.record_success()
                    return result
                    
                except Exception as exc:
                    last_exception = exc
                    error_class = classify_error(exc, config)
                    
                    # Update stats
                    if error_class == ErrorClass.PERMANENT:
                        stats.permanent_errors += 1
                    else:
                        stats.transient_errors += 1
                    stats.last_error = f"{type(exc).__name__}: {str(exc)[:100]}"
                    stats.last_error_time = datetime.now()
                    
                    # Handle permanent errors
                    if error_class == ErrorClass.PERMANENT:
                        stats.failed_calls += 1
                        if cb:
                            cb.record_failure()
                        if config.log_retries:
                            logger.warning(
                                f"{config.log_prefix} Permanent error on {func_name}: {exc}"
                            )
                        if reraise_permanent:
                            raise
                        return None
                    
                    # Last attempt - don't retry
                    if attempt >= config.max_attempts - 1:
                        stats.failed_calls += 1
                        if cb:
                            cb.record_failure()
                        raise
                    
                    # Calculate delay and wait
                    delay = calculate_delay(attempt, config)
                    total_delay += delay
                    stats.total_retries += 1
                    stats.total_delay_seconds += delay
                    
                    if config.log_retries:
                        logger.info(
                            f"{config.log_prefix} {func_name} attempt {attempt + 1}/{config.max_attempts} "
                            f"failed ({error_class.name}): {type(exc).__name__}. "
                            f"Retrying in {delay:.1f}s..."
                        )
                    
                    # Callback
                    if on_retry:
                        try:
                            on_retry(exc, attempt + 1)
                        except Exception:
                            pass
                    
                    time.sleep(delay)
            
            # Should not reach here, but just in case
            if last_exception:
                raise last_exception
        
        # Attach metadata for introspection
        wrapper._retry_config = config
        wrapper._retry_func_name = func_name
        
        return wrapper
    
    return decorator


class CircuitBreakerOpen(Exception):
    """Raised when circuit breaker prevents a call."""
    pass


class RetryExhausted(Exception):
    """Raised when all retry attempts are exhausted."""
    pass


# ============================================================================
# Convenience wrappers for common use cases
# ============================================================================

def retry_api_call(
    max_attempts: int = 3,
    base_delay: float = 1.0,
    rate_limit_delay: float = 5.0,
):
    """
    Retry decorator optimized for REST API calls.
    
    - Longer delay on 429 (rate limit)
    - Fast fail on auth errors (401, 403)
    - Retries on server errors (500, 502, 503, 504)
    """
    def decorator(func: Callable) -> Callable:
        @smart_retry(
            max_attempts=max_attempts,
            base_delay=base_delay,
            transient_errors=[429, 500, 502, 503, 504],
            permanent_errors=[400, 401, 403, 404, 405, 410, 422],
            log_prefix="[API]",
        )
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                # Extra delay for rate limiting
                if hasattr(exc, 'response') and exc.response is not None:
                    if exc.response.status_code == 429:
                        logger.warning(f"[API] Rate limited, waiting {rate_limit_delay}s...")
                        time.sleep(rate_limit_delay)
                raise
        return wrapper
    return decorator


def retry_dns_lookup(max_attempts: int = 3):
    """Retry decorator optimized for DNS lookups."""
    import socket
    
    return smart_retry(
        max_attempts=max_attempts,
        base_delay=0.5,
        max_delay=5.0,
        transient_exceptions=(
            socket.gaierror,
            socket.timeout,
            TimeoutError,
            ConnectionError,
        ),
        log_prefix="[DNS]",
    )


def retry_network_request(max_attempts: int = 3, timeout_multiplier: float = 1.0):
    """
    Retry decorator for general network requests.
    
    Args:
        max_attempts: Max retry attempts
        timeout_multiplier: Multiplier for delays (useful for Tor)
    """
    return smart_retry(
        max_attempts=max_attempts,
        base_delay=1.0 * timeout_multiplier,
        max_delay=30.0 * timeout_multiplier,
        transient_exceptions=(
            TimeoutError,
            ConnectionError,
            ConnectionResetError,
            ConnectionRefusedError,
            OSError,
        ),
        log_prefix="[Net]",
    )

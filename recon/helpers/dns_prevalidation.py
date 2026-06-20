"""
RedAmon - DNS Pre-Validation
=============================
Validates DNS resolution before port scanning to filter out stale subdomains.

Prevents wasting scan time on:
- Subdomains that no longer resolve (NXDOMAIN)
- Stale DNS entries
- Wildcard DNS responses

Usage:
    from recon.helpers import DNSPreValidator
    
    validator = DNSPreValidator()
    
    # Validate before port scanning
    subdomains = ["www.example.com", "api.example.com", "old.example.com"]
    valid, invalid = validator.validate_batch(subdomains)
    
    # valid = ["www.example.com", "api.example.com"]
    # invalid = {"old.example.com": "NXDOMAIN"}
    
    # Run port scan only on valid subdomains
    run_port_scan(valid)
"""

import concurrent.futures
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional
import threading
import random

try:
    import dns.resolver
    import dns.exception
    HAS_DNSPYTHON = True
except ImportError:
    HAS_DNSPYTHON = False


@dataclass
class DNSValidationResult:
    """Result of DNS validation for a single host."""
    hostname: str
    is_valid: bool
    resolved_ips: list[str] = field(default_factory=list)
    failure_reason: Optional[str] = None
    is_wildcard: bool = False
    response_time_ms: float = 0.0
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class DNSPreValidator:
    """
    Pre-validates DNS resolution for subdomains before scanning.
    
    Features:
    - Batch validation with concurrent resolution
    - Wildcard detection (random subdomain test)
    - Response time tracking
    - Caching of results
    - Configurable resolvers
    """
    
    # Default public resolvers
    DEFAULT_RESOLVERS = [
        '8.8.8.8',       # Google
        '8.8.4.4',       # Google
        '1.1.1.1',       # Cloudflare
        '1.0.0.1',       # Cloudflare
        '9.9.9.9',       # Quad9
        '208.67.222.222', # OpenDNS
    ]
    
    def __init__(
        self,
        resolvers: list[str] | None = None,
        timeout: float = 5.0,
        max_workers: int = 50,
        cache_results: bool = True,
        detect_wildcards: bool = True,
    ):
        """
        Initialize DNS pre-validator.
        
        Args:
            resolvers: List of DNS resolver IPs (uses defaults if None)
            timeout: DNS query timeout in seconds
            max_workers: Max concurrent DNS queries
            cache_results: Whether to cache validation results
            detect_wildcards: Whether to check for wildcard DNS
        """
        self.resolvers = resolvers or self.DEFAULT_RESOLVERS
        self.timeout = timeout
        self.max_workers = max_workers
        self.cache_results = cache_results
        self.detect_wildcards = detect_wildcards
        
        self._cache: dict[str, DNSValidationResult] = {}
        self._cache_lock = threading.Lock()
        self._wildcard_cache: dict[str, set[str]] = {}  # domain -> wildcard IPs
        
        self._stats = {
            'total_validated': 0,
            'valid_count': 0,
            'invalid_count': 0,
            'wildcard_count': 0,
            'cache_hits': 0,
            'total_time_ms': 0.0,
        }
        
        # Configure dnspython resolver if available
        if HAS_DNSPYTHON:
            self._resolver = dns.resolver.Resolver()
            self._resolver.nameservers = self.resolvers
            self._resolver.timeout = timeout
            self._resolver.lifetime = timeout * 2
    
    def _get_root_domain(self, hostname: str) -> str:
        """Extract root domain from hostname."""
        parts = hostname.lower().strip('.').split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return hostname
    
    def _detect_wildcard(self, root_domain: str) -> set[str]:
        """
        Detect wildcard DNS by querying random non-existent subdomain.
        
        Returns set of IPs that are wildcard responses.
        """
        if root_domain in self._wildcard_cache:
            return self._wildcard_cache[root_domain]
        
        # Generate random subdomain
        random_sub = f"redamon-wildcard-test-{random.randint(100000, 999999)}.{root_domain}"
        
        wildcard_ips = set()
        try:
            if HAS_DNSPYTHON:
                answers = self._resolver.resolve(random_sub, 'A')
                wildcard_ips = {str(rdata) for rdata in answers}
            else:
                # Fallback to socket
                _, _, ips = socket.gethostbyname_ex(random_sub)
                wildcard_ips = set(ips)
        except Exception:
            # No wildcard (expected - random subdomain shouldn't resolve)
            pass
        
        self._wildcard_cache[root_domain] = wildcard_ips
        if wildcard_ips:
            print(f"[*][DNS] Wildcard detected for {root_domain}: {wildcard_ips}")
        
        return wildcard_ips
    
    def _resolve_single(self, hostname: str) -> DNSValidationResult:
        """Resolve a single hostname."""
        hostname = hostname.lower().strip()
        
        # Check cache
        if self.cache_results:
            with self._cache_lock:
                if hostname in self._cache:
                    self._stats['cache_hits'] += 1
                    return self._cache[hostname]
        
        start_time = time.time()
        result = DNSValidationResult(hostname=hostname, is_valid=False)
        
        try:
            if HAS_DNSPYTHON:
                # Use dnspython for better error handling
                answers = self._resolver.resolve(hostname, 'A')
                result.resolved_ips = [str(rdata) for rdata in answers]
                result.is_valid = True
            else:
                # Fallback to socket
                ip = socket.gethostbyname(hostname)
                result.resolved_ips = [ip]
                result.is_valid = True
                
        except dns.resolver.NXDOMAIN if HAS_DNSPYTHON else socket.gaierror:
            result.failure_reason = "NXDOMAIN"
        except dns.resolver.NoAnswer if HAS_DNSPYTHON else Exception:
            result.failure_reason = "NoAnswer"
        except dns.resolver.NoNameservers if HAS_DNSPYTHON else Exception:
            result.failure_reason = "NoNameservers"
        except dns.exception.Timeout if HAS_DNSPYTHON else socket.timeout:
            result.failure_reason = "Timeout"
        except socket.gaierror as e:
            if e.errno == socket.EAI_NONAME:
                result.failure_reason = "NXDOMAIN"
            else:
                result.failure_reason = f"DNS error: {e}"
        except Exception as e:
            result.failure_reason = str(e)[:100]
        
        result.response_time_ms = (time.time() - start_time) * 1000
        
        # Check for wildcard
        if result.is_valid and self.detect_wildcards:
            root_domain = self._get_root_domain(hostname)
            wildcard_ips = self._detect_wildcard(root_domain)
            if wildcard_ips and set(result.resolved_ips).issubset(wildcard_ips):
                result.is_wildcard = True
                result.is_valid = False
                result.failure_reason = "WildcardMatch"
        
        # Cache result
        if self.cache_results:
            with self._cache_lock:
                self._cache[hostname] = result
        
        return result
    
    def validate(self, hostname: str) -> DNSValidationResult:
        """
        Validate a single hostname.
        
        Args:
            hostname: Hostname to validate
            
        Returns:
            DNSValidationResult with validation details
        """
        result = self._resolve_single(hostname)
        
        # Update stats
        self._stats['total_validated'] += 1
        if result.is_valid:
            self._stats['valid_count'] += 1
        else:
            self._stats['invalid_count'] += 1
        if result.is_wildcard:
            self._stats['wildcard_count'] += 1
        self._stats['total_time_ms'] += result.response_time_ms
        
        return result
    
    def validate_batch(
        self,
        hostnames: list[str],
        progress_callback: callable | None = None,
    ) -> tuple[list[str], dict[str, str]]:
        """
        Validate a batch of hostnames concurrently.
        
        Args:
            hostnames: List of hostnames to validate
            progress_callback: Optional callback(completed, total) for progress
            
        Returns:
            Tuple of (valid_hostnames, invalid_dict)
            invalid_dict maps hostname -> failure reason
        """
        if not hostnames:
            return [], {}
        
        valid = []
        invalid = {}
        total = len(hostnames)
        completed = 0
        
        # Deduplicate
        unique_hosts = list(set(h.lower().strip() for h in hostnames if h))
        
        print(f"[*][DNS] Pre-validating {len(unique_hosts)} hostnames...")
        start_time = time.time()
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_host = {
                executor.submit(self._resolve_single, host): host
                for host in unique_hosts
            }
            
            for future in concurrent.futures.as_completed(future_to_host):
                hostname = future_to_host[future]
                completed += 1
                
                try:
                    result = future.result()
                    
                    # Update stats
                    self._stats['total_validated'] += 1
                    self._stats['total_time_ms'] += result.response_time_ms
                    
                    if result.is_valid:
                        valid.append(hostname)
                        self._stats['valid_count'] += 1
                    else:
                        invalid[hostname] = result.failure_reason or "Unknown"
                        self._stats['invalid_count'] += 1
                        if result.is_wildcard:
                            self._stats['wildcard_count'] += 1
                            
                except Exception as e:
                    invalid[hostname] = f"Error: {str(e)[:50]}"
                    self._stats['invalid_count'] += 1
                
                if progress_callback and completed % 100 == 0:
                    progress_callback(completed, total)
        
        elapsed = time.time() - start_time
        
        # Summary
        print(f"[+][DNS] Validation complete in {elapsed:.1f}s:")
        print(f"    Valid: {len(valid)}/{len(unique_hosts)}")
        print(f"    Invalid (NXDOMAIN/timeout): {len(invalid)}")
        if self._stats['wildcard_count'] > 0:
            print(f"    Wildcard matches filtered: {self._stats['wildcard_count']}")
        
        return valid, invalid
    
    def get_stats(self) -> dict:
        """Get validation statistics."""
        return {
            **self._stats,
            'avg_response_ms': (
                self._stats['total_time_ms'] / max(1, self._stats['total_validated'])
            ),
            'cache_size': len(self._cache),
            'wildcard_domains': len(self._wildcard_cache),
        }
    
    def clear_cache(self):
        """Clear the validation cache."""
        with self._cache_lock:
            self._cache.clear()
        self._wildcard_cache.clear()


def prevalidate_subdomains(
    subdomains: list[str],
    resolvers: list[str] | None = None,
    timeout: float = 5.0,
    max_workers: int = 50,
    detect_wildcards: bool = True,
) -> tuple[list[str], dict[str, str]]:
    """
    Convenience function to pre-validate subdomains before port scanning.
    
    Args:
        subdomains: List of subdomains to validate
        resolvers: Custom DNS resolvers (optional)
        timeout: DNS query timeout
        max_workers: Concurrent workers
        detect_wildcards: Whether to filter wildcard responses
    
    Returns:
        Tuple of (valid_subdomains, invalid_dict)
    
    Usage:
        valid, invalid = prevalidate_subdomains(subdomains)
        # Use 'valid' for port scanning
        # Log 'invalid' for reporting
    """
    validator = DNSPreValidator(
        resolvers=resolvers,
        timeout=timeout,
        max_workers=max_workers,
        detect_wildcards=detect_wildcards,
    )
    
    return validator.validate_batch(subdomains)


def filter_dns_stale(
    dns_results: dict,
    subdomains_to_check: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """
    Filter DNS results to find stale entries that no longer resolve.
    
    This is useful when you have existing DNS data and want to verify
    it's still valid before scanning.
    
    Args:
        dns_results: DNS resolution results dict (from domain_recon)
        subdomains_to_check: Optional subset to check (default: all)
    
    Returns:
        Tuple of (still_valid, now_stale) hostname lists
    """
    subdomains = dns_results.get('subdomains', {})
    
    if subdomains_to_check:
        to_check = [s for s in subdomains_to_check if s in subdomains]
    else:
        to_check = list(subdomains.keys())
    
    validator = DNSPreValidator(detect_wildcards=False)
    valid, invalid = validator.validate_batch(to_check)
    
    stale = list(invalid.keys())
    
    if stale:
        print(f"[!][DNS] Found {len(stale)} stale DNS entries (no longer resolve)")
    
    return valid, stale

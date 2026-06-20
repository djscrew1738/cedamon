"""
RedAmon - Network Health Check
==============================
Pre-scan network health assessment for Tor/proxy connectivity.

Verifies that anonymity layers are working correctly before starting
resource-intensive scans. Prevents wasted scan time on failing circuits.
"""

import socket
import time
from dataclasses import dataclass
from statistics import mean, stdev
from typing import Optional

try:
    import requests
except ImportError:
    requests = None

try:
    import socks
except ImportError:
    socks = None


@dataclass
class HealthCheckResult:
    """Result of a single health check probe."""
    success: bool
    latency_ms: float
    error: str = ""
    ip_address: str = ""


@dataclass
class NetworkHealthReport:
    """Comprehensive network health assessment."""
    healthy: bool
    action: str  # 'proceed', 'reduce_rate', 'abort', 'fallback_direct'
    success_rate: float
    avg_latency_ms: float
    latency_stddev_ms: float
    min_latency_ms: float
    max_latency_ms: float
    suggested_rate: Optional[int]
    message: str
    details: list[HealthCheckResult]
    ip_addresses: list[str]
    
    def to_dict(self) -> dict:
        return {
            "healthy": self.healthy,
            "action": self.action,
            "success_rate": round(self.success_rate, 2),
            "avg_latency_ms": round(self.avg_latency_ms, 1),
            "latency_stddev_ms": round(self.latency_stddev_ms, 1),
            "min_latency_ms": round(self.min_latency_ms, 1),
            "max_latency_ms": round(self.max_latency_ms, 1),
            "suggested_rate": self.suggested_rate,
            "message": self.message,
            "unique_ips": len(set(self.ip_addresses)),
            "probe_count": len(self.details),
        }


# Tor check endpoints
TOR_CHECK_URLS = [
    "https://check.torproject.org/api/ip",
    "https://api.ipify.org?format=json",
    "https://ifconfig.me/ip",
]

# Thresholds for health assessment
HEALTH_THRESHOLDS = {
    "min_success_rate": 0.6,  # At least 60% of probes must succeed
    "critical_success_rate": 0.3,  # Below this, abort
    "high_latency_ms": 10000,  # Above this, reduce rate
    "very_high_latency_ms": 20000,  # Above this, abort
    "acceptable_latency_ms": 5000,  # Below this, proceed normally
}


def check_tor_port(host: str = "127.0.0.1", port: int = 9050, timeout: float = 5.0) -> bool:
    """Check if Tor SOCKS port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def probe_tor_circuit(
    url: str = None,
    timeout: float = 30.0,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 9050,
) -> HealthCheckResult:
    """
    Probe a single Tor circuit by making an HTTP request.
    
    Args:
        url: URL to fetch (default: Tor check API)
        timeout: Request timeout in seconds
        proxy_host: SOCKS proxy host
        proxy_port: SOCKS proxy port
        
    Returns:
        HealthCheckResult with latency and IP information
    """
    if requests is None:
        return HealthCheckResult(
            success=False,
            latency_ms=0,
            error="requests library not available",
        )
    
    url = url or TOR_CHECK_URLS[0]
    proxies = {
        "http": f"socks5h://{proxy_host}:{proxy_port}",
        "https": f"socks5h://{proxy_host}:{proxy_port}",
    }
    
    start = time.time()
    try:
        resp = requests.get(
            url,
            proxies=proxies,
            timeout=timeout,
            headers={"User-Agent": "RedAmon-HealthCheck/1.0"},
        )
        latency_ms = (time.time() - start) * 1000
        
        if resp.ok:
            # Try to extract IP from response
            ip_address = ""
            try:
                data = resp.json()
                ip_address = data.get("IP") or data.get("ip") or ""
            except Exception:
                # Plain text response (e.g., ifconfig.me)
                ip_address = resp.text.strip()[:45]
            
            return HealthCheckResult(
                success=True,
                latency_ms=latency_ms,
                ip_address=ip_address,
            )
        else:
            return HealthCheckResult(
                success=False,
                latency_ms=latency_ms,
                error=f"HTTP {resp.status_code}",
            )
    
    except requests.exceptions.Timeout:
        return HealthCheckResult(
            success=False,
            latency_ms=timeout * 1000,
            error="Timeout",
        )
    except requests.exceptions.ProxyError as e:
        return HealthCheckResult(
            success=False,
            latency_ms=(time.time() - start) * 1000,
            error=f"Proxy error: {str(e)[:100]}",
        )
    except Exception as e:
        return HealthCheckResult(
            success=False,
            latency_ms=(time.time() - start) * 1000,
            error=str(e)[:100],
        )


def request_new_tor_circuit(control_port: int = 9051, password: str = "") -> bool:
    """
    Request a new Tor circuit via the control port.
    
    Requires Tor control port to be enabled and accessible.
    
    Args:
        control_port: Tor control port (default: 9051)
        password: Control port password if set
        
    Returns:
        True if circuit renewal was successful
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect(("127.0.0.1", control_port))
        
        # Authenticate
        if password:
            sock.send(f'AUTHENTICATE "{password}"\r\n'.encode())
        else:
            sock.send(b'AUTHENTICATE\r\n')
        
        response = sock.recv(1024).decode()
        if "250" not in response:
            sock.close()
            return False
        
        # Request new circuit
        sock.send(b'SIGNAL NEWNYM\r\n')
        response = sock.recv(1024).decode()
        sock.close()
        
        return "250" in response
    
    except Exception as e:
        print(f"[!][TorHealth] Failed to request new circuit: {e}")
        return False


def assess_tor_health(
    probe_count: int = 5,
    timeout_per_probe: float = 30.0,
    proxy_host: str = "127.0.0.1",
    proxy_port: int = 9050,
) -> NetworkHealthReport:
    """
    Assess Tor network health before scanning.
    
    Runs multiple probes through Tor and analyzes:
    - Success rate (how many probes complete)
    - Latency distribution
    - IP diversity (are circuits changing?)
    
    Args:
        probe_count: Number of probes to run
        timeout_per_probe: Timeout for each probe
        proxy_host: SOCKS proxy host
        proxy_port: SOCKS proxy port
        
    Returns:
        NetworkHealthReport with health assessment and recommendations
    """
    # First check if Tor port is even reachable
    if not check_tor_port(proxy_host, proxy_port):
        return NetworkHealthReport(
            healthy=False,
            action="abort",
            success_rate=0.0,
            avg_latency_ms=0.0,
            latency_stddev_ms=0.0,
            min_latency_ms=0.0,
            max_latency_ms=0.0,
            suggested_rate=None,
            message=f"Tor SOCKS proxy not reachable at {proxy_host}:{proxy_port}",
            details=[],
            ip_addresses=[],
        )
    
    # Run probes
    results = []
    for i in range(probe_count):
        # Rotate through check URLs to avoid rate limiting
        url = TOR_CHECK_URLS[i % len(TOR_CHECK_URLS)]
        result = probe_tor_circuit(url, timeout_per_probe, proxy_host, proxy_port)
        results.append(result)
        
        # Small delay between probes
        if i < probe_count - 1:
            time.sleep(0.5)
    
    # Analyze results
    successes = [r for r in results if r.success]
    success_rate = len(successes) / len(results) if results else 0.0
    
    latencies = [r.latency_ms for r in successes] if successes else [0.0]
    avg_latency = mean(latencies)
    latency_std = stdev(latencies) if len(latencies) > 1 else 0.0
    min_latency = min(latencies)
    max_latency = max(latencies)
    
    ip_addresses = [r.ip_address for r in successes if r.ip_address]
    
    # Determine health and action
    thresholds = HEALTH_THRESHOLDS
    
    if success_rate < thresholds["critical_success_rate"]:
        return NetworkHealthReport(
            healthy=False,
            action="abort",
            success_rate=success_rate,
            avg_latency_ms=avg_latency,
            latency_stddev_ms=latency_std,
            min_latency_ms=min_latency,
            max_latency_ms=max_latency,
            suggested_rate=None,
            message=f"Critical: Only {success_rate:.0%} of Tor probes succeeded. Tor circuits are failing.",
            details=results,
            ip_addresses=ip_addresses,
        )
    
    if success_rate < thresholds["min_success_rate"]:
        return NetworkHealthReport(
            healthy=False,
            action="fallback_direct",
            success_rate=success_rate,
            avg_latency_ms=avg_latency,
            latency_stddev_ms=latency_std,
            min_latency_ms=min_latency,
            max_latency_ms=max_latency,
            suggested_rate=None,
            message=f"Tor unreliable ({success_rate:.0%} success). Consider scanning without Tor.",
            details=results,
            ip_addresses=ip_addresses,
        )
    
    if avg_latency > thresholds["very_high_latency_ms"]:
        return NetworkHealthReport(
            healthy=False,
            action="abort",
            success_rate=success_rate,
            avg_latency_ms=avg_latency,
            latency_stddev_ms=latency_std,
            min_latency_ms=min_latency,
            max_latency_ms=max_latency,
            suggested_rate=None,
            message=f"Tor latency too high ({avg_latency:.0f}ms). Scans will timeout.",
            details=results,
            ip_addresses=ip_addresses,
        )
    
    if avg_latency > thresholds["high_latency_ms"]:
        # Suggest reduced rate based on latency
        suggested_rate = max(5, int(1000 / (avg_latency / 1000)))  # ~1 req per RTT
        return NetworkHealthReport(
            healthy=True,
            action="reduce_rate",
            success_rate=success_rate,
            avg_latency_ms=avg_latency,
            latency_stddev_ms=latency_std,
            min_latency_ms=min_latency,
            max_latency_ms=max_latency,
            suggested_rate=suggested_rate,
            message=f"Tor latency elevated ({avg_latency:.0f}ms). Reducing rate to {suggested_rate} rps.",
            details=results,
            ip_addresses=ip_addresses,
        )
    
    # Healthy
    return NetworkHealthReport(
        healthy=True,
        action="proceed",
        success_rate=success_rate,
        avg_latency_ms=avg_latency,
        latency_stddev_ms=latency_std,
        min_latency_ms=min_latency,
        max_latency_ms=max_latency,
        suggested_rate=None,
        message=f"Tor healthy: {success_rate:.0%} success, {avg_latency:.0f}ms avg latency",
        details=results,
        ip_addresses=ip_addresses,
    )


def assess_direct_connectivity(
    test_urls: list[str] = None,
    probe_count: int = 3,
    timeout: float = 10.0,
) -> NetworkHealthReport:
    """
    Assess direct (non-Tor) network connectivity.
    
    Args:
        test_urls: URLs to test (default: common health endpoints)
        timeout: Request timeout
        
    Returns:
        NetworkHealthReport for direct connectivity
    """
    if requests is None:
        return NetworkHealthReport(
            healthy=False,
            action="abort",
            success_rate=0.0,
            avg_latency_ms=0.0,
            latency_stddev_ms=0.0,
            min_latency_ms=0.0,
            max_latency_ms=0.0,
            suggested_rate=None,
            message="requests library not available",
            details=[],
            ip_addresses=[],
        )
    
    test_urls = test_urls or [
        "https://httpbin.org/ip",
        "https://api.ipify.org?format=json",
        "https://ifconfig.me/ip",
    ]
    
    results = []
    for i in range(probe_count):
        url = test_urls[i % len(test_urls)]
        start = time.time()
        try:
            resp = requests.get(url, timeout=timeout)
            latency_ms = (time.time() - start) * 1000
            
            ip_address = ""
            try:
                data = resp.json()
                ip_address = data.get("origin") or data.get("ip") or ""
            except Exception:
                ip_address = resp.text.strip()[:45]
            
            results.append(HealthCheckResult(
                success=resp.ok,
                latency_ms=latency_ms,
                ip_address=ip_address,
            ))
        except Exception as e:
            results.append(HealthCheckResult(
                success=False,
                latency_ms=(time.time() - start) * 1000,
                error=str(e)[:100],
            ))
    
    successes = [r for r in results if r.success]
    success_rate = len(successes) / len(results) if results else 0.0
    latencies = [r.latency_ms for r in successes] if successes else [0.0]
    
    return NetworkHealthReport(
        healthy=success_rate >= 0.6,
        action="proceed" if success_rate >= 0.6 else "abort",
        success_rate=success_rate,
        avg_latency_ms=mean(latencies),
        latency_stddev_ms=stdev(latencies) if len(latencies) > 1 else 0.0,
        min_latency_ms=min(latencies),
        max_latency_ms=max(latencies),
        suggested_rate=None,
        message=f"Direct connectivity: {success_rate:.0%} success, {mean(latencies):.0f}ms avg",
        details=results,
        ip_addresses=[r.ip_address for r in successes if r.ip_address],
    )


def run_pre_scan_health_check(
    use_tor: bool = True,
    probe_count: int = 5,
    auto_adjust_settings: bool = True,
) -> dict:
    """
    Run comprehensive pre-scan network health check.
    
    Args:
        use_tor: Whether Tor is configured for the scan
        probe_count: Number of probes per check
        auto_adjust_settings: Return suggested setting adjustments
        
    Returns:
        Health check results with recommendations
    """
    print("\n[*][NetworkHealth] Running pre-scan network health check...")
    
    results = {
        "tor": None,
        "direct": None,
        "recommendation": None,
        "settings_adjustments": {},
    }
    
    if use_tor:
        print("[*][NetworkHealth] Checking Tor connectivity...")
        tor_health = assess_tor_health(probe_count=probe_count)
        results["tor"] = tor_health.to_dict()
        
        if tor_health.healthy:
            print(f"[✓][NetworkHealth] Tor: {tor_health.message}")
            results["recommendation"] = "proceed_with_tor"
            
            if tor_health.action == "reduce_rate" and auto_adjust_settings:
                results["settings_adjustments"] = {
                    "NUCLEI_RATE_LIMIT": tor_health.suggested_rate,
                    "HTTPX_RATE_LIMIT": tor_health.suggested_rate,
                    "KATANA_RATE_LIMIT": tor_health.suggested_rate,
                }
                print(f"[*][NetworkHealth] Suggesting rate limit: {tor_health.suggested_rate} rps")
        else:
            print(f"[!][NetworkHealth] Tor: {tor_health.message}")
            
            if tor_health.action == "fallback_direct":
                print("[*][NetworkHealth] Checking direct connectivity as fallback...")
                direct_health = assess_direct_connectivity(probe_count=probe_count)
                results["direct"] = direct_health.to_dict()
                
                if direct_health.healthy:
                    print(f"[✓][NetworkHealth] Direct: {direct_health.message}")
                    results["recommendation"] = "fallback_to_direct"
                    if auto_adjust_settings:
                        results["settings_adjustments"]["USE_TOR_FOR_RECON"] = False
                else:
                    results["recommendation"] = "abort_network_issues"
            else:
                results["recommendation"] = "abort_tor_failed"
    else:
        print("[*][NetworkHealth] Checking direct connectivity...")
        direct_health = assess_direct_connectivity(probe_count=probe_count)
        results["direct"] = direct_health.to_dict()
        
        if direct_health.healthy:
            print(f"[✓][NetworkHealth] Direct: {direct_health.message}")
            results["recommendation"] = "proceed_direct"
        else:
            print(f"[!][NetworkHealth] Direct: {direct_health.message}")
            results["recommendation"] = "abort_network_issues"
    
    print(f"[*][NetworkHealth] Recommendation: {results['recommendation']}")
    
    return results

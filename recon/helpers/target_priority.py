"""
RedAmon - Target Prioritization Queue
======================================
Prioritizes scan targets based on attack surface indicators.

Scans high-value targets first:
- CMS/WordPress/Drupal get highest priority
- Exposed admin panels prioritized
- Dynamic content (PHP/ASP/JSP) prioritized
- More open ports = higher priority
- CDN/WAF protected endpoints deprioritized

Usage:
    from recon.helpers import TargetPriorityQueue
    
    queue = TargetPriorityQueue()
    
    # Add targets with http_probe data
    for target, info in http_probe['by_url'].items():
        queue.add_target(target, info)
    
    # Process in priority order
    for target, score, reasons in queue.get_prioritized():
        scan_target(target)
"""

import heapq
from dataclasses import dataclass, field
from typing import Any, Optional
from urllib.parse import urlparse
import re


@dataclass
class ScoredTarget:
    """A target with its priority score and reasons."""
    url: str
    score: int
    reasons: list[str]
    metadata: dict = field(default_factory=dict)
    
    def __lt__(self, other):
        # Higher score = higher priority (min-heap inverted)
        return self.score > other.score
    
    def __eq__(self, other):
        return self.score == other.score


class TargetPriorityQueue:
    """
    Priority queue for scan targets based on attack surface analysis.
    
    Scoring Rules:
    - High-value technologies: +50 (CMS, vulnerable frameworks)
    - Admin/management panels: +40
    - Authentication endpoints: +35
    - API endpoints: +30
    - Dynamic content: +25
    - Multiple open ports: +5 per port
    - Sensitive file types: +20
    - CDN/WAF protected: -30
    - Static content: -20
    """
    
    # Technology patterns that indicate high-value targets
    HIGH_VALUE_TECH = {
        # CMS - High value, many known CVEs
        'wordpress': 50,
        'drupal': 50,
        'joomla': 50,
        'magento': 45,
        'shopify': 35,
        'woocommerce': 45,
        'prestashop': 40,
        'opencart': 40,
        
        # Vulnerable frameworks
        'struts': 50,
        'apache struts': 50,
        'spring': 40,
        'spring boot': 40,
        'laravel': 35,
        'rails': 35,
        'django': 30,
        'flask': 30,
        
        # Panel software
        'phpmyadmin': 45,
        'cpanel': 45,
        'plesk': 45,
        'webmin': 45,
        'grafana': 40,
        'kibana': 40,
        'jenkins': 50,
        'gitlab': 40,
        'sonarqube': 40,
        
        # Rich web apps
        'angular': 25,
        'react': 25,
        'vue': 25,
        'next.js': 25,
        'nuxt': 25,
    }
    
    # URL patterns for admin/management
    ADMIN_PATTERNS = [
        r'/admin',
        r'/administrator',
        r'/manager',
        r'/cms',
        r'/control',
        r'/panel',
        r'/dashboard',
        r'/wp-admin',
        r'/backend',
        r'/console',
        r'/portal',
        r'/cpanel',
        r'/webmail',
        r'/phpmyadmin',
        r'/adminer',
    ]
    
    # URL patterns for authentication
    AUTH_PATTERNS = [
        r'/login',
        r'/signin',
        r'/auth',
        r'/oauth',
        r'/sso',
        r'/saml',
        r'/register',
        r'/signup',
        r'/account',
        r'/password',
        r'/forgot',
        r'/reset',
        r'/2fa',
        r'/mfa',
    ]
    
    # URL patterns for API endpoints
    API_PATTERNS = [
        r'/api/',
        r'/api/v\d',
        r'/rest/',
        r'/graphql',
        r'/v\d/',
        r'/ws/',
        r'/websocket',
        r'\.json$',
        r'\.xml$',
    ]
    
    # Dynamic content indicators
    DYNAMIC_EXTENSIONS = {
        '.php': 25,
        '.asp': 25,
        '.aspx': 25,
        '.jsp': 25,
        '.do': 20,
        '.action': 20,
        '.cgi': 20,
        '.pl': 15,
    }
    
    # CDN/WAF indicators (deprioritize)
    CDN_WAF_INDICATORS = [
        'cloudflare',
        'akamai',
        'fastly',
        'cloudfront',
        'incapsula',
        'sucuri',
        'imperva',
        'stackpath',
        'azure cdn',
        'verizon edgecast',
    ]
    
    # Static content (deprioritize)
    STATIC_PATTERNS = [
        r'/static/',
        r'/assets/',
        r'/images/',
        r'/img/',
        r'/css/',
        r'/js/',
        r'/fonts/',
        r'/media/',
        r'\.min\.js$',
        r'\.min\.css$',
    ]
    
    def __init__(self):
        self._heap: list[ScoredTarget] = []
        self._seen: set[str] = set()
        self._stats = {
            'total_added': 0,
            'duplicates_skipped': 0,
            'high_priority': 0,
            'low_priority': 0,
        }
    
    def add_target(self, url: str, http_info: dict | None = None,
                   port_info: dict | None = None, extra_score: int = 0,
                   extra_reasons: list[str] | None = None):
        """
        Add a target to the priority queue.
        
        Args:
            url: Target URL
            http_info: HTTP probe data (technologies, status, headers)
            port_info: Port scan data (open ports, services)
            extra_score: Additional score adjustment
            extra_reasons: Additional scoring reasons
        """
        # Normalize URL
        url = url.strip().lower()
        if url in self._seen:
            self._stats['duplicates_skipped'] += 1
            return
        
        self._seen.add(url)
        self._stats['total_added'] += 1
        
        score = 0
        reasons = list(extra_reasons or [])
        
        # Score based on HTTP probe data
        if http_info:
            tech_score, tech_reasons = self._score_technologies(http_info)
            score += tech_score
            reasons.extend(tech_reasons)
            
            cdn_score, cdn_reasons = self._score_cdn_waf(http_info)
            score += cdn_score
            reasons.extend(cdn_reasons)
        
        # Score based on URL patterns
        url_score, url_reasons = self._score_url_patterns(url)
        score += url_score
        reasons.extend(url_reasons)
        
        # Score based on port info
        if port_info:
            port_score, port_reasons = self._score_ports(port_info)
            score += port_score
            reasons.extend(port_reasons)
        
        # Add extra score
        score += extra_score
        
        # Create scored target
        target = ScoredTarget(
            url=url,
            score=score,
            reasons=reasons,
            metadata={
                'http_info': http_info,
                'port_info': port_info,
            }
        )
        
        heapq.heappush(self._heap, target)
        
        # Update stats
        if score >= 50:
            self._stats['high_priority'] += 1
        elif score < 0:
            self._stats['low_priority'] += 1
    
    def _score_technologies(self, http_info: dict) -> tuple[int, list[str]]:
        """Score based on detected technologies."""
        score = 0
        reasons = []
        
        technologies = http_info.get('technologies', [])
        if isinstance(technologies, str):
            technologies = [technologies]
        
        for tech in technologies:
            tech_lower = tech.lower() if isinstance(tech, str) else str(tech).lower()
            for pattern, points in self.HIGH_VALUE_TECH.items():
                if pattern in tech_lower:
                    score += points
                    reasons.append(f"Tech:{tech}(+{points})")
                    break
        
        return score, reasons
    
    def _score_cdn_waf(self, http_info: dict) -> tuple[int, list[str]]:
        """Score (negative) for CDN/WAF protection."""
        score = 0
        reasons = []
        
        # Check server header
        server = http_info.get('server', '').lower()
        for indicator in self.CDN_WAF_INDICATORS:
            if indicator in server:
                score -= 30
                reasons.append(f"CDN/WAF:{indicator}(-30)")
                break
        
        # Check CDN flag
        if http_info.get('cdn'):
            if score >= 0:  # Don't double-penalize
                score -= 20
                reasons.append("CDN-protected(-20)")
        
        return score, reasons
    
    def _score_url_patterns(self, url: str) -> tuple[int, list[str]]:
        """Score based on URL patterns."""
        score = 0
        reasons = []
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        
        # Admin/management patterns
        for pattern in self.ADMIN_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                score += 40
                reasons.append(f"Admin-panel(+40)")
                break
        
        # Authentication patterns
        for pattern in self.AUTH_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                score += 35
                reasons.append(f"Auth-endpoint(+35)")
                break
        
        # API patterns
        for pattern in self.API_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                score += 30
                reasons.append(f"API-endpoint(+30)")
                break
        
        # Dynamic content
        for ext, points in self.DYNAMIC_EXTENSIONS.items():
            if path.endswith(ext):
                score += points
                reasons.append(f"Dynamic:{ext}(+{points})")
                break
        
        # Static content (negative)
        for pattern in self.STATIC_PATTERNS:
            if re.search(pattern, path, re.IGNORECASE):
                score -= 20
                reasons.append(f"Static-content(-20)")
                break
        
        return score, reasons
    
    def _score_ports(self, port_info: dict) -> tuple[int, list[str]]:
        """Score based on open ports."""
        score = 0
        reasons = []
        
        ports = port_info.get('ports', [])
        if not isinstance(ports, list):
            ports = [ports] if ports else []
        
        # More ports = larger attack surface
        if len(ports) > 1:
            port_bonus = min(len(ports) * 5, 30)  # Cap at +30
            score += port_bonus
            reasons.append(f"Ports:{len(ports)}(+{port_bonus})")
        
        # High-value ports
        high_value_ports = {
            22: ('SSH', 10),
            23: ('Telnet', 15),
            3306: ('MySQL', 20),
            5432: ('PostgreSQL', 20),
            27017: ('MongoDB', 20),
            6379: ('Redis', 25),
            11211: ('Memcached', 20),
            9200: ('Elasticsearch', 20),
            8080: ('Alt-HTTP', 10),
            8443: ('Alt-HTTPS', 10),
            9000: ('Debug', 15),
            9090: ('Prometheus', 15),
        }
        
        for port in ports:
            if isinstance(port, dict):
                port_num = port.get('port')
            else:
                port_num = int(port) if str(port).isdigit() else None
            
            if port_num in high_value_ports:
                name, points = high_value_ports[port_num]
                score += points
                reasons.append(f"Port:{port_num}/{name}(+{points})")
        
        return score, reasons
    
    def get_prioritized(self) -> list[tuple[str, int, list[str]]]:
        """
        Get all targets in priority order (highest first).
        
        Returns:
            List of (url, score, reasons) tuples
        """
        # Sort heap and return
        sorted_targets = sorted(self._heap)
        return [(t.url, t.score, t.reasons) for t in sorted_targets]
    
    def pop(self) -> tuple[str, int, list[str]] | None:
        """Pop the highest priority target."""
        if not self._heap:
            return None
        target = heapq.heappop(self._heap)
        return (target.url, target.score, target.reasons)
    
    def peek(self) -> tuple[str, int, list[str]] | None:
        """Peek at the highest priority target without removing."""
        if not self._heap:
            return None
        target = self._heap[0]
        return (target.url, target.score, target.reasons)
    
    def __len__(self) -> int:
        return len(self._heap)
    
    def __bool__(self) -> bool:
        return len(self._heap) > 0
    
    def get_stats(self) -> dict:
        """Get queue statistics."""
        if not self._heap:
            return {**self._stats, 'queue_size': 0}
        
        scores = [t.score for t in self._heap]
        return {
            **self._stats,
            'queue_size': len(self._heap),
            'min_score': min(scores),
            'max_score': max(scores),
            'avg_score': sum(scores) / len(scores),
        }
    
    def get_top_n(self, n: int = 10) -> list[tuple[str, int, list[str]]]:
        """Get top N highest priority targets."""
        sorted_targets = sorted(self._heap)[:n]
        return [(t.url, t.score, t.reasons) for t in sorted_targets]
    
    def get_low_priority(self, threshold: int = 0) -> list[str]:
        """Get targets below a score threshold."""
        return [t.url for t in self._heap if t.score < threshold]


def prioritize_from_http_probe(http_probe: dict, 
                                port_scan: dict | None = None) -> TargetPriorityQueue:
    """
    Build a priority queue from http_probe and optional port_scan results.
    
    Args:
        http_probe: HTTP probe results with 'by_url' dict
        port_scan: Optional port scan results with 'by_host' dict
    
    Returns:
        Populated TargetPriorityQueue
    """
    queue = TargetPriorityQueue()
    
    # Build port info lookup by host
    port_lookup = {}
    if port_scan and 'by_host' in port_scan:
        for host, info in port_scan['by_host'].items():
            port_lookup[host.lower()] = {
                'ports': info.get('port_details', []),
            }
    
    # Add targets from http_probe
    by_url = http_probe.get('by_url', {})
    for url, info in by_url.items():
        # Get port info for this host
        parsed = urlparse(url)
        host = parsed.hostname or ''
        port_info = port_lookup.get(host.lower())
        
        queue.add_target(url, http_info=info, port_info=port_info)
    
    return queue


def print_priority_summary(queue: TargetPriorityQueue, top_n: int = 10):
    """Print a summary of the priority queue."""
    stats = queue.get_stats()
    print(f"\n[*] Target Priority Summary")
    print(f"    Total targets: {stats['queue_size']}")
    print(f"    High priority (>50): {stats['high_priority']}")
    print(f"    Low priority (<0): {stats['low_priority']}")
    print(f"    Score range: {stats.get('min_score', 0)} to {stats.get('max_score', 0)}")
    
    print(f"\n[*] Top {top_n} Targets:")
    for i, (url, score, reasons) in enumerate(queue.get_top_n(top_n), 1):
        reason_str = ', '.join(reasons[:3])
        if len(reasons) > 3:
            reason_str += f" +{len(reasons)-3} more"
        print(f"    {i}. [{score:+3d}] {url[:60]}...")
        print(f"        Reasons: {reason_str}")

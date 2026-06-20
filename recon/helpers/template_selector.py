"""
RedAmon - Service-Aware Template Selection
==========================================
Select relevant Nuclei templates based on detected technologies and services.

Uses fingerprints from httpx (Wappalyzer), nmap, and banner grabbing to build
a targeted template set, skipping irrelevant templates for faster, more
accurate scans.
"""

from typing import Optional


# Technology to template mapping
# Maps detected technologies/services to relevant Nuclei template paths
TECH_TEMPLATE_MAP: dict[str, list[str]] = {
    # CMS Platforms
    "wordpress": [
        "http/cves/wordpress/",
        "http/vulnerabilities/wordpress/",
        "http/exposed-panels/wordpress/",
        "http/misconfiguration/wordpress/",
        "http/technologies/wordpress/",
    ],
    "drupal": [
        "http/cves/drupal/",
        "http/vulnerabilities/drupal/",
        "http/exposed-panels/drupal/",
    ],
    "joomla": [
        "http/cves/joomla/",
        "http/vulnerabilities/joomla/",
        "http/exposed-panels/joomla/",
    ],
    "magento": [
        "http/cves/magento/",
        "http/vulnerabilities/magento/",
        "http/exposed-panels/magento/",
    ],
    "shopify": [
        "http/technologies/shopify/",
    ],
    "woocommerce": [
        "http/cves/wordpress/",
        "http/vulnerabilities/wordpress/",
        "http/technologies/woocommerce/",
    ],
    "ghost": [
        "http/cves/ghost/",
        "http/exposed-panels/ghost/",
    ],
    "strapi": [
        "http/cves/strapi/",
        "http/vulnerabilities/strapi/",
    ],
    
    # Web Servers
    "nginx": [
        "http/cves/nginx/",
        "http/misconfiguration/nginx/",
        "http/vulnerabilities/nginx/",
    ],
    "apache": [
        "http/cves/apache/",
        "http/misconfiguration/apache/",
        "http/vulnerabilities/apache/",
    ],
    "iis": [
        "http/cves/microsoft/iis/",
        "http/misconfiguration/iis/",
    ],
    "tomcat": [
        "http/cves/apache/tomcat/",
        "http/vulnerabilities/apache/tomcat/",
        "http/exposed-panels/tomcat/",
    ],
    "jetty": [
        "http/cves/jetty/",
        "http/misconfiguration/jetty/",
    ],
    "caddy": [
        "http/misconfiguration/caddy/",
    ],
    "lighttpd": [
        "http/cves/lighttpd/",
    ],
    
    # Languages & Frameworks
    "php": [
        "http/cves/php/",
        "http/vulnerabilities/php/",
        "http/misconfiguration/php/",
    ],
    "laravel": [
        "http/cves/laravel/",
        "http/vulnerabilities/laravel/",
        "http/exposed-panels/laravel/",
        "http/misconfiguration/laravel/",
    ],
    "symfony": [
        "http/cves/symfony/",
        "http/misconfiguration/symfony/",
    ],
    "codeigniter": [
        "http/cves/codeigniter/",
    ],
    "nodejs": [
        "http/cves/nodejs/",
        "http/vulnerabilities/nodejs/",
    ],
    "express": [
        "http/cves/express/",
        "http/misconfiguration/express/",
    ],
    "nextjs": [
        "http/cves/nextjs/",
        "http/vulnerabilities/nextjs/",
    ],
    "nuxt": [
        "http/cves/nuxt/",
    ],
    "django": [
        "http/cves/django/",
        "http/vulnerabilities/django/",
        "http/misconfiguration/django/",
    ],
    "flask": [
        "http/cves/flask/",
        "http/vulnerabilities/flask/",
    ],
    "fastapi": [
        "http/cves/fastapi/",
    ],
    "rails": [
        "http/cves/rails/",
        "http/vulnerabilities/rails/",
    ],
    "ruby": [
        "http/cves/ruby/",
    ],
    "spring": [
        "http/cves/spring/",
        "http/vulnerabilities/spring/",
        "http/misconfiguration/spring/",
    ],
    "java": [
        "http/cves/java/",
        "http/vulnerabilities/java/",
    ],
    "dotnet": [
        "http/cves/microsoft/",
        "http/vulnerabilities/aspnet/",
    ],
    "aspnet": [
        "http/cves/microsoft/",
        "http/vulnerabilities/aspnet/",
    ],
    
    # Databases
    "mysql": [
        "network/cves/mysql/",
        "http/cves/phpmyadmin/",
    ],
    "postgresql": [
        "network/cves/postgresql/",
    ],
    "mongodb": [
        "network/cves/mongodb/",
        "http/exposed-panels/mongodb/",
    ],
    "redis": [
        "network/cves/redis/",
        "http/exposed-panels/redis/",
    ],
    "elasticsearch": [
        "http/cves/elasticsearch/",
        "http/exposed-panels/elasticsearch/",
        "http/misconfiguration/elasticsearch/",
    ],
    "couchdb": [
        "http/cves/couchdb/",
        "http/exposed-panels/couchdb/",
    ],
    "cassandra": [
        "network/cves/cassandra/",
    ],
    "mssql": [
        "network/cves/mssql/",
    ],
    "oracle": [
        "network/cves/oracle/",
    ],
    
    # CI/CD & DevOps
    "jenkins": [
        "http/cves/jenkins/",
        "http/vulnerabilities/jenkins/",
        "http/exposed-panels/jenkins/",
    ],
    "gitlab": [
        "http/cves/gitlab/",
        "http/vulnerabilities/gitlab/",
        "http/exposed-panels/gitlab/",
    ],
    "github": [
        "http/cves/github/",
    ],
    "bitbucket": [
        "http/cves/bitbucket/",
        "http/exposed-panels/bitbucket/",
    ],
    "bamboo": [
        "http/cves/bamboo/",
        "http/exposed-panels/bamboo/",
    ],
    "teamcity": [
        "http/cves/teamcity/",
        "http/exposed-panels/teamcity/",
    ],
    "sonarqube": [
        "http/cves/sonarqube/",
        "http/exposed-panels/sonarqube/",
    ],
    "nexus": [
        "http/cves/nexus/",
        "http/exposed-panels/nexus/",
    ],
    "artifactory": [
        "http/cves/artifactory/",
        "http/exposed-panels/artifactory/",
    ],
    "ansible": [
        "http/cves/ansible/",
        "http/exposed-panels/ansible/",
    ],
    
    # Cloud & Containers
    "docker": [
        "http/cves/docker/",
        "http/exposed-panels/docker/",
        "http/misconfiguration/docker/",
    ],
    "kubernetes": [
        "http/cves/kubernetes/",
        "http/exposed-panels/kubernetes/",
        "http/misconfiguration/kubernetes/",
    ],
    "aws": [
        "http/cves/aws/",
        "http/exposures/configs/aws/",
        "http/misconfiguration/aws/",
    ],
    "azure": [
        "http/cves/azure/",
        "http/misconfiguration/azure/",
    ],
    "gcp": [
        "http/cves/google/",
        "http/misconfiguration/gcp/",
    ],
    "cloudflare": [
        "http/misconfiguration/cloudflare/",
    ],
    
    # Monitoring & Logging
    "grafana": [
        "http/cves/grafana/",
        "http/exposed-panels/grafana/",
        "http/vulnerabilities/grafana/",
    ],
    "prometheus": [
        "http/exposed-panels/prometheus/",
        "http/misconfiguration/prometheus/",
    ],
    "kibana": [
        "http/cves/kibana/",
        "http/exposed-panels/kibana/",
    ],
    "splunk": [
        "http/cves/splunk/",
        "http/exposed-panels/splunk/",
    ],
    "datadog": [
        "http/misconfiguration/datadog/",
    ],
    "zabbix": [
        "http/cves/zabbix/",
        "http/exposed-panels/zabbix/",
    ],
    "nagios": [
        "http/cves/nagios/",
        "http/exposed-panels/nagios/",
    ],
    
    # Networking
    "cisco": [
        "http/cves/cisco/",
        "network/cves/cisco/",
        "http/exposed-panels/cisco/",
    ],
    "fortinet": [
        "http/cves/fortinet/",
        "http/exposed-panels/fortinet/",
    ],
    "paloalto": [
        "http/cves/paloalto/",
        "http/exposed-panels/paloalto/",
    ],
    "juniper": [
        "http/cves/juniper/",
        "network/cves/juniper/",
    ],
    "mikrotik": [
        "http/cves/mikrotik/",
        "network/cves/mikrotik/",
    ],
    "sonicwall": [
        "http/cves/sonicwall/",
    ],
    "f5": [
        "http/cves/f5/",
        "http/exposed-panels/f5/",
    ],
    
    # AI & ML
    "ollama": [
        "http/cves/ollama/",
        "http/exposed-panels/ollama/",
    ],
    "jupyter": [
        "http/cves/jupyter/",
        "http/exposed-panels/jupyter/",
        "http/misconfiguration/jupyter/",
    ],
    "mlflow": [
        "http/exposed-panels/mlflow/",
    ],
    "huggingface": [
        "http/misconfiguration/huggingface/",
    ],
    
    # Other common services
    "rabbitmq": [
        "http/cves/rabbitmq/",
        "http/exposed-panels/rabbitmq/",
    ],
    "kafka": [
        "http/cves/kafka/",
    ],
    "activemq": [
        "http/cves/activemq/",
        "http/exposed-panels/activemq/",
    ],
    "memcached": [
        "network/cves/memcached/",
    ],
    "haproxy": [
        "http/cves/haproxy/",
        "http/misconfiguration/haproxy/",
    ],
    "varnish": [
        "http/misconfiguration/varnish/",
    ],
    "traefik": [
        "http/cves/traefik/",
        "http/exposed-panels/traefik/",
    ],
    "kong": [
        "http/cves/kong/",
    ],
}

# Server header patterns -> technology
SERVER_PATTERNS: dict[str, str] = {
    "nginx": "nginx",
    "apache": "apache",
    "iis": "iis",
    "tomcat": "tomcat",
    "jetty": "jetty",
    "caddy": "caddy",
    "lighttpd": "lighttpd",
    "gunicorn": "python",
    "uvicorn": "python",
    "werkzeug": "flask",
    "openresty": "nginx",
    "cloudflare": "cloudflare",
    "varnish": "varnish",
    "haproxy": "haproxy",
    "traefik": "traefik",
}

# Universal templates that should always be included
UNIVERSAL_TEMPLATES = [
    "http/cves/generic/",
    "http/vulnerabilities/generic/",
    "http/misconfiguration/generic/",
    "http/exposures/",
    "http/default-logins/",
    "http/takeovers/",
]

# High-value templates for common vulnerability classes
VULN_CLASS_TEMPLATES = {
    "injection": [
        "http/fuzzing/",
        "dast/vulnerabilities/sqli/",
        "dast/vulnerabilities/xss/",
        "dast/vulnerabilities/ssti/",
    ],
    "exposure": [
        "http/exposures/",
        "http/exposed-panels/",
        "http/misconfiguration/",
    ],
    "auth": [
        "http/default-logins/",
        "http/vulnerabilities/auth/",
    ],
}


def normalize_tech_name(tech: str) -> str:
    """Normalize technology name for lookup."""
    if not tech:
        return ""
    
    normalized = tech.lower().strip()
    
    # Common aliases
    aliases = {
        "wordpress.org": "wordpress",
        "wp": "wordpress",
        "nginx inc": "nginx",
        "apache http server": "apache",
        "microsoft-iis": "iis",
        "microsoft iis": "iis",
        "node.js": "nodejs",
        "node": "nodejs",
        "express.js": "express",
        "next.js": "nextjs",
        "nuxt.js": "nuxt",
        "ruby on rails": "rails",
        "asp.net": "aspnet",
        ".net": "dotnet",
        "amazon web services": "aws",
        "google cloud platform": "gcp",
        "microsoft azure": "azure",
        "elastic": "elasticsearch",
    }
    
    # Check exact match first
    if normalized in aliases:
        return aliases[normalized]
    
    # Check partial matches
    for alias, canonical in aliases.items():
        if alias in normalized:
            return canonical
    
    return normalized


def extract_tech_from_server_header(server: str) -> Optional[str]:
    """Extract technology from Server header."""
    if not server:
        return None
    
    server_lower = server.lower()
    for pattern, tech in SERVER_PATTERNS.items():
        if pattern in server_lower:
            return tech
    return None


def select_templates_for_fingerprint(
    technologies: list[str] = None,
    servers: list[str] = None,
    ports: list[int] = None,
    include_universal: bool = True,
    include_dast: bool = False,
    max_templates: int = 0,
) -> dict:
    """
    Select relevant Nuclei templates based on detected fingerprints.
    
    Args:
        technologies: List of technologies detected by Wappalyzer/httpx
        servers: List of Server headers detected
        ports: List of open ports (used for service-specific templates)
        include_universal: Include universal templates that apply to all targets
        include_dast: Include DAST/fuzzing templates
        max_templates: Maximum template paths to return (0 = unlimited)
        
    Returns:
        Dictionary with:
        - templates: List of template paths
        - matched_technologies: Technologies that had template mappings
        - unmatched_technologies: Technologies without mappings
        - reasoning: Explanation of selection
    """
    selected_templates: set[str] = set()
    matched_techs: set[str] = set()
    unmatched_techs: set[str] = set()
    reasoning: list[str] = []
    
    # Process technologies
    for tech in (technologies or []):
        normalized = normalize_tech_name(tech)
        if not normalized:
            continue
            
        if normalized in TECH_TEMPLATE_MAP:
            templates = TECH_TEMPLATE_MAP[normalized]
            selected_templates.update(templates)
            matched_techs.add(normalized)
            reasoning.append(f"Added {len(templates)} templates for {normalized}")
        else:
            unmatched_techs.add(tech)
    
    # Process server headers
    for server in (servers or []):
        tech = extract_tech_from_server_header(server)
        if tech and tech in TECH_TEMPLATE_MAP:
            templates = TECH_TEMPLATE_MAP[tech]
            selected_templates.update(templates)
            matched_techs.add(tech)
            reasoning.append(f"Added {len(templates)} templates from Server header: {server}")
    
    # Add port-specific templates
    port_tech_map = {
        3306: "mysql",
        5432: "postgresql",
        27017: "mongodb",
        6379: "redis",
        9200: "elasticsearch",
        5601: "kibana",
        3000: "grafana",
        9090: "prometheus",
        8080: "jenkins",  # Common but ambiguous
        11434: "ollama",
        8888: "jupyter",
    }
    
    for port in (ports or []):
        if port in port_tech_map:
            tech = port_tech_map[port]
            if tech in TECH_TEMPLATE_MAP:
                templates = TECH_TEMPLATE_MAP[tech]
                selected_templates.update(templates)
                reasoning.append(f"Added templates for port {port} ({tech})")
    
    # Add universal templates
    if include_universal:
        selected_templates.update(UNIVERSAL_TEMPLATES)
        reasoning.append(f"Added {len(UNIVERSAL_TEMPLATES)} universal templates")
    
    # Add DAST templates
    if include_dast:
        for vuln_class, templates in VULN_CLASS_TEMPLATES.items():
            selected_templates.update(templates)
        reasoning.append("Added DAST/fuzzing templates")
    
    # Convert to sorted list
    template_list = sorted(selected_templates)
    
    # Apply max limit if specified
    if max_templates > 0 and len(template_list) > max_templates:
        template_list = template_list[:max_templates]
        reasoning.append(f"Limited to {max_templates} templates")
    
    return {
        "templates": template_list,
        "matched_technologies": sorted(matched_techs),
        "unmatched_technologies": sorted(unmatched_techs),
        "template_count": len(template_list),
        "reasoning": reasoning,
    }


def select_templates_from_http_probe(http_probe_data: dict, settings: dict = None) -> dict:
    """
    Select templates based on http_probe results.
    
    Args:
        http_probe_data: HTTP probe results from http_probe.py
        settings: Project settings for configuration
        
    Returns:
        Template selection result
    """
    settings = settings or {}
    
    # Extract technologies from http_probe
    technologies = []
    servers = []
    
    # From technologies_found (aggregated)
    tech_found = http_probe_data.get("technologies_found", {})
    technologies.extend(tech_found.keys())
    
    # From by_url entries
    for url, entry in http_probe_data.get("by_url", {}).items():
        # Technologies per URL
        url_techs = entry.get("technologies", [])
        if isinstance(url_techs, list):
            technologies.extend(url_techs)
        
        # Server headers
        server = entry.get("server", "")
        if server:
            servers.append(server)
    
    # Deduplicate
    technologies = list(set(technologies))
    servers = list(set(servers))
    
    # Get DAST setting
    include_dast = settings.get("NUCLEI_DAST_MODE", False)
    
    return select_templates_for_fingerprint(
        technologies=technologies,
        servers=servers,
        include_universal=True,
        include_dast=include_dast,
    )


def build_nuclei_template_args(selection_result: dict) -> list[str]:
    """
    Build Nuclei command-line arguments from template selection.
    
    Args:
        selection_result: Result from select_templates_for_fingerprint
        
    Returns:
        List of -t arguments for Nuclei command
    """
    args = []
    for template_path in selection_result.get("templates", []):
        args.extend(["-t", template_path])
    return args


def print_template_selection_summary(selection_result: dict):
    """Print a human-readable summary of template selection."""
    print(f"\n[*][TemplateSelector] Service-Aware Template Selection")
    print(f"    Matched technologies: {', '.join(selection_result['matched_technologies']) or 'None'}")
    print(f"    Unmatched: {', '.join(selection_result['unmatched_technologies'][:5]) or 'None'}")
    print(f"    Selected templates: {selection_result['template_count']}")
    for reason in selection_result['reasoning'][-5:]:
        print(f"      • {reason}")

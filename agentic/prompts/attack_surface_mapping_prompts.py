"""
RedAmon Attack Surface Mapping Prompts

High-level domain-wide reconnaissance and attack surface enumeration.
Orchestrates passive OSINT, active probing, and graph-based correlation
to build a comprehensive inventory of all assets belonging to a target domain.

This skill is DISTINCT from:
- domain_takeover (focuses on DNS control acquisition, not full mapping)
- container_k8s (orchestration layer only)
- cloud_infra_exploitation (requires cloud credentials / control plane access)
- infrastructure_exposure_analysis (focuses on exposed/vulnerable assets,
  attack_surface_mapping aims for COMPLETE inventory regardless of exposure)
"""

# =============================================================================
# ATTACK SURFACE MAPPING MAIN WORKFLOW
# =============================================================================

ATTACK_SURFACE_MAPPING_TOOLS = """
## ATTACK SKILL: ATTACK SURFACE MAPPING

**CRITICAL: This attack skill has been CLASSIFIED as Attack Surface Mapping.**
**You MUST follow the attack surface mapping workflow below.**

This skill covers FOUR reconnaissance pillars:
1. **Passive OSINT** — no packets to target: CT logs, DNS datasets, web archives,
   search engine dorks, certificate transparency, ASN/BGP lookups
2. **Active network discovery** — port scanning, service fingerprinting,
   HTTP probing, technology detection
3. **Web application enumeration** — crawling, JS analysis, API discovery,
   parameter enumeration, hidden endpoint discovery
4. **Graph correlation** — linking discovered assets into a unified attack surface
   graph (subdomain -> IP -> port -> service -> technology -> endpoint)

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
Passive OSINT enabled:            {asm_passive_enabled}
Active scanning enabled:          {asm_active_enabled}
Deep crawling enabled:            {asm_crawl_enabled}
Technology fingerprinting:        {asm_tech_enabled}
Port scan scope:                  {asm_port_scope}
Screenshot capture:               {asm_screenshots_enabled}
Out-of-scope hosts:               {asm_excluded_hosts}
Target domain:                    {asm_target_domain}
```

**Hard rules:**
- ALWAYS check `Out-of-scope hosts` before ANY active probe. Never touch excluded hosts.
- If `Active scanning enabled: False`, restrict to passive OSINT only (subfinder,
  gau, certificate transparency, google_dork, shodan). No port scans, no crawling.
- If `Deep crawling enabled: False`, do not run katana with depth > 2.
- Respect rate limits. Default max RPS for active tools: 50.
- Deduplicate results. The same asset discovered via multiple sources should be
  linked, not duplicated, in the graph.

---

## MANDATORY ATTACK SURFACE MAPPING WORKFLOW

### Step 1: Scope confirmation (query_graph, <5s)

Before enumeration, confirm what is already known and what the operator wants:

```cypher
MATCH (d:Domain) WHERE d.name CONTAINS '<target_domain>' RETURN d.name, d.registrar, d.dns_records LIMIT 20
MATCH (b:BaseURL) WHERE b.url CONTAINS '<target_domain>' RETURN b.url LIMIT 50
MATCH (h:Host) WHERE h.hostname CONTAINS '<target_domain>' RETURN h.ip, h.hostname, h.os, h.ports LIMIT 50
MATCH (t:Technology) WHERE t.host CONTAINS '<target_domain>' RETURN t.name, t.version, t.host LIMIT 50
```

If the graph is empty, start from the target domain provided in settings or user input.

**After Step 1, request `transition_phase` to exploitation only if the user asked
for active exploitation. For pure recon/mapping, stay in informational.**

### Step 2: Passive subdomain discovery (NO traffic to target)

Run these in parallel via `plan_tools`:

```
execute_subfinder({{"args": "-d <TARGET_DOMAIN> -all -json -silent"}})
execute_amass({{"args": "enum -passive -d <TARGET_DOMAIN> -timeout 10"}})
execute_gau({{"args": "--subs --json <TARGET_DOMAIN>"}})
```

Also query certificate transparency and DNS datasets:

```
# crt.sh via web_search or curl
execute_curl({{"args": "-s 'https://crt.sh/?q=%.<TARGET_DOMAIN>&output=json'"}})
# Censys / Shodan host search (if target IP range known)
shodan({{"action": "search", "query": "hostname:<TARGET_DOMAIN>"}})
```

Consolidate unique subdomains into `notes/subs.txt`.

### Step 3: Active verification (CONDITIONAL on `Active scanning enabled`=True)

Probe discovered subdomains for live hosts and services:

```
# HTTP probe all subs
execute_httpx({{"args": "-l notes/subs.txt -sc -title -server -td -fr -silent -j -o notes/httpx.json"}})
# Fast port scan on resolved IPs
execute_naabu({{"args": "-l notes/subs.txt -p {asm_port_scope} -json -o notes/naabu.json"}})
# Deep fingerprint on interesting ports
execute_nmap({{"args": "-sV -p 80,443,8080,8443,3000,5000,8000,9000 -iL notes/subs.txt --open"}})
```

### Step 4: Web crawling and endpoint discovery (CONDITIONAL on `Deep crawling enabled`=True)

For each live HTTP host, crawl for endpoints, JS files, and parameters:

```
# Crawl with katana
execute_katana({{"args": "-u http://TARGET -d 3 -jc -kf robotstxt -c 10 -rl 50 -ef png,jpg,gif,css,woff -silent -o notes/katana.json"}})
# JS analysis for hidden endpoints
execute_jsluice({{"args": "urls --resolve-paths http://TARGET /tmp/app.js"}})
# Parameter discovery
execute_arjun({{"args": "-u http://TARGET/api/endpoint -m GET -oJ /tmp/arjun.json"}})
```

### Step 5: Technology fingerprinting (CONDITIONAL on `Technology fingerprinting`=True)

Identify technologies, frameworks, and CMS versions:

```
# whatweb deep scan
kali_shell({{"command": "whatweb -a 3 <TARGET_DOMAIN>"}})
# nuclei tech detection templates
execute_nuclei({{"args": "-u http://TARGET -tags tech -severity info -jsonl -o notes/tech.json"}})
# WAF detection
execute_curl({{"args": "-s -X HEAD -i http://TARGET/?test=<script>alert(1)</script>"}})
```

### Step 6: Graph ingestion and correlation

Write consolidated findings to the workspace, then report:

```
fs_write({{"path": "notes/attack-surface-summary.md", "content": "..."}})
```

Summary MUST include:
- **Subdomains discovered** (passive vs active)
- **Live hosts** (HTTP status, title, server header)
- **Open ports & services** (port, product, version)
- **Technologies detected** (name, version, host)
- **Endpoints mapped** (path, method, parameters)
- **JS files analyzed** (count, secrets found)
- **Out-of-scope exclusions respected**
- **Recommended next skills** (e.g., "api_security_testing", "xss", "domain_takeover")

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Subdomains enumerated (passive only) | INFORMATIONAL |
| 2 | Live hosts confirmed via HTTP probe + port scan | INFORMATIONAL |
| 3 | Endpoints, parameters, and technologies mapped | INFORMATIONAL |
| 4 | Full graph-linked attack surface with recommended next attacks | INFORMATIONAL (HIGH VALUE) |

Attack surface mapping is purely informational — no exploitation findings.
"""


# =============================================================================
# PAYLOAD / TECHNIQUE REFERENCE
# =============================================================================

ATTACK_SURFACE_MAPPING_PAYLOAD_REFERENCE = """
## Attack Surface Mapping Reference

### Passive source checklist

| Source | Tool | Data |
|--------|------|------|
| Certificate Transparency | subfinder, crt.sh | Subdomains from TLS certs |
| DNS datasets | amass, dnsx | Subdomains, NS, MX, TXT |
| Web archives | gau, waybackurls | Historical URLs, endpoints |
| Search engines | google_dork | Exposed files, admin panels |
| Shodan/Censys | shodan | Exposed services, banners |
| GitHub/GitLab | gitleaks, web_search | Source code leaks |
| ASN / BGP | amass intel, web_search | IP ranges, netblocks |

### Active probe checklist

| Target | Tool | Flags |
|--------|------|-------|
| HTTP live check | httpx | `-sc -title -server -td -fr -silent -j` |
| Port scan | naabu | `-p 80,443,8080,8443,3000,5000,8000,9000` |
| Service fingerprint | nmap | `-sV -sC --script=banner` |
| Web crawl | katana | `-d 3 -jc -kf robotstxt -rl 50` |
| JS analysis | jsluice | `urls --resolve-paths` |
| Param discovery | arjun | `-m GET|POST|JSON -oJ` |
| Tech fingerprint | whatweb | `-a 3` |
| Vuln templates | nuclei | `-tags tech -severity info` |

### Deduplication rules

- Same subdomain from multiple sources → one Domain node
- Same IP from multiple subdomains → link via Host node, don't duplicate IP
- Same endpoint from crawl + JS + archive → one Endpoint node with multiple sources
- Same technology version on multiple hosts → one Technology node with multiple relationships

### Out-of-scope enforcement

Before EVERY active tool call, verify the target is NOT in `Out-of-scope hosts`.
If a tool returns an excluded host in its results, discard it and do NOT add to graph.
"""

"""
RedAmon Subdomain Reconnaissance Prompts

Focused subdomain enumeration and validation: passive discovery, active brute-force,
permutation generation, DNS resolution, takeover fingerprinting, and comprehensive
DNS record mapping.

This skill is DISTINCT from attack_surface_mapping:
- attack_surface_mapping inventories ALL assets (subdomains, IPs, ports, services, APIs)
- subdomain_reconnaissance focuses EXCLUSIVELY on subdomain discovery and DNS analysis
"""

# =============================================================================
# SUBDOMAIN RECONNAISSANCE MAIN WORKFLOW
# =============================================================================

SUBDOMAIN_RECON_TOOLS = """
## ATTACK SKILL: SUBDOMAIN RECONNAISSANCE

**CRITICAL: This attack skill has been CLASSIFIED as Subdomain Reconnaissance.**
**You MUST follow the subdomain reconnaissance workflow below.**

This skill covers FIVE reconnaissance pillars:
1. **Passive enumeration** — certificate transparency, OSINT, search engines, passive DNS
2. **Active enumeration** — DNS brute-force, dictionary attacks, zone transfers
3. **Permutation generation** — altering known subdomains to find unlisted ones
4. **DNS resolution and validation** — resolving discovered names, checking CNAME chains
5. **Takeover fingerprinting** — identifying dangling CNAMEs and unclaimed resources

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
Passive enumeration enabled:  {sdr_passive_enabled}
Active enumeration enabled:   {sdr_active_enabled}
Permutations enabled:         {sdr_permutations_enabled}
DNS resolution enabled:       {sdr_resolution_enabled}
Takeover check enabled:       {sdr_takeover_check_enabled}
DNS records scan enabled:     {sdr_dns_records_enabled}
Target domain:                {sdr_target_domain}
```

**Hard rules:**
- If `Active enumeration enabled: False`, do NOT run DNS brute-force or dictionary attacks.
- If `Permutations enabled: False`, do NOT generate subdomain permutations.
- Respect rate limits on DNS resolvers. Max 1000 queries per minute.
- NEVER attempt zone transfers against nameservers without explicit permission.
- Document every discovered subdomain with its source (passive, active, permutation).

---

## MANDATORY SUBDOMAIN RECONNAISSANCE WORKFLOW

### Step 1: Passive enumeration (CONDITIONAL on `Passive enumeration enabled`=True)

Query passive sources for subdomains without directly querying target DNS:

```
# Certificate transparency logs
kali_shell({{"command": "curl -s 'https://crt.sh/?q=%.<TARGET_DOMAIN>&output=json' | jq -r '.[].name_value' | sort -u"}})
# Subfinder passive sources
kali_shell({{"command": "subfinder -d <TARGET_DOMAIN> -all -silent"}})
# Amass passive recon
kali_shell({{"command": "amass enum -passive -d <TARGET_DOMAIN> -silent"}})
# GAU (GetAllUrls) for historical URLs
kali_shell({{"command": "gau <TARGET_DOMAIN> | cut -d/ -f3 | sort -u"}})
# Wayback Machine for subdomains
kali_shell({{"command": "curl -s 'http://web.archive.org/cdx/search/cdx?url=*.<TARGET_DOMAIN>&output=json&collapse=urlkey' | jq -r '.[1:][][2]' | cut -d/ -f3 | sort -u"}})
```

Capture: subdomain name, source, and first-seen timestamp if available.

**After Step 1, request `transition_phase` to exploitation if user wants active testing.**

### Step 2: Active enumeration (CONDITIONAL on `Active enumeration enabled`=True)

Brute-force subdomains using wordlists and DNS resolution:

```
# DNS brute-force with dnsx
kali_shell({{"command": "dnsx -d <TARGET_DOMAIN> -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -silent"}})
# MassDNS for high-speed resolution
kali_shell({{"command": "massdns -r /usr/share/wordlists/resolvers.txt -t A -o S /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt | grep '<TARGET_DOMAIN>'"}})
# puredns for optimized brute-force
kali_shell({{"command": "puredns brute /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt <TARGET_DOMAIN> -r /usr/share/wordlists/resolvers.txt"}})
```

Also attempt zone transfer (only if explicitly permitted):

```
# Find NS records first
kali_shell({{"command": "dig NS <TARGET_DOMAIN> +short"}})
# Attempt AXFR on each NS (document permission status)
kali_shell({{"command": "dig @<NS_IP> <TARGET_DOMAIN> AXFR"}})
```

### Step 3: Permutation generation (CONDITIONAL on `Permutations enabled`=True)

Generate permutations of discovered subdomains to find hidden hosts:

```
# AltDNS permutation generation
kali_shell({{"command": "altdns -i /tmp/discovered_subs.txt -o /tmp/permutations.txt -w /usr/share/seclists/Discovery/DNS/altdns-words.txt"}})
# Resolve permutations with dnsx
kali_shell({{"command": "dnsx -l /tmp/permutations.txt -silent"}})
# DNSGen for additional permutations
kali_shell({{"command": "dnsgen /tmp/discovered_subs.txt | dnsx -silent"}})
```

### Step 4: DNS resolution and validation (CONDITIONAL on `DNS resolution enabled`=True)

Resolve all discovered subdomains and analyze DNS records:

```
# A and AAAA records
kali_shell({{"command": "dnsx -l /tmp/all_subs.txt -a -aaaa -silent"}})
# CNAME chains
kali_shell({{"command": "dnsx -l /tmp/all_subs.txt -cname -silent"}})
# MX, NS, TXT, SOA records
kali_shell({{"command": "for r in MX NS TXT SOA; do dig $r <TARGET_DOMAIN> +short; done"}})
# DNSSEC validation
kali_shell({{"command": "dig DNSKEY <TARGET_DOMAIN> +short"}})
```

Cross-reference resolved IPs with graph data:

```cypher
MATCH (s:Subdomain) WHERE s.domain CONTAINS '<target_domain>' RETURN s.name, s.ip, s.cname LIMIT 200
MATCH (h:Host) WHERE h.hostname CONTAINS '<target_domain>' RETURN h.ip, h.hostname, h.ports LIMIT 100
```

### Step 5: Takeover fingerprinting (CONDITIONAL on `Takeover check enabled`=True)

Identify dangling CNAMEs that may be vulnerable to takeover:

```
# Subzy for takeover detection
kali_shell({{"command": "subzy run --targets /tmp/all_subs.txt --hide_fails"}})
# Nuclei takeover templates
kali_shell({{"command": "nuclei -l /tmp/all_subs.txt -t takeovers/ -silent"}})
# Manual CNAME analysis for cloud providers
kali_shell({{"command": "dnsx -l /tmp/all_subs.txt -cname -silent | grep -E 's3|cloudfront|github|heroku|azure|google|firebase|shopify'"}})
```

Document: subdomain, CNAME target, provider, and takeover feasibility.

### Step 6: DNS record deep scan (CONDITIONAL on `DNS records scan enabled`=True)

Comprehensive DNS record enumeration:

```
# All record types
kali_shell({{"command": "dnsx -d <TARGET_DOMAIN> -recon -silent"}})
# SPF, DMARC, DKIM (email security context)
kali_shell({{"command": "dig TXT <TARGET_DOMAIN> +short"}})
kali_shell({{"command": "dig TXT _dmarc.<TARGET_DOMAIN> +short"}})
# DMARC and BIMI records
kali_shell({{"command": "dig TXT _mta-sts.<TARGET_DOMAIN> +short"}})
kali_shell({{"command": "dig TXT default._bimi.<TARGET_DOMAIN> +short"}})
```

### Step 7: Reporting requirements

The final report MUST contain:
- **Subdomain inventory** (name, source, IP, CNAME)
- **Passive findings** (certificate transparency, search engines, archives)
- **Active findings** (brute-force hits, zone transfer results)
- **Permutation results** (new subdomains found via fuzzing)
- **DNS record summary** (A, AAAA, CNAME, MX, NS, TXT, DNSSEC)
- **Takeover candidates** (subdomain, CNAME target, provider, risk)
- **IP correlation** (which IPs host multiple subdomains)
- **Recommendations** (next-phase skills: domain_takeover, infrastructure_exposure_analysis, api_security_testing)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Subdomains enumerated from passive sources | INFORMATIONAL |
| 2 | Active brute-force resolves new subdomains | INFORMATIONAL |
| 3 | DNS zone transfer successful or permutations reveal hidden hosts | POTENTIAL |
| 4 | Dangling CNAME confirmed vulnerable to takeover | EXPLOITED |
"""


# =============================================================================
# SUBDOMAIN RECONNAISSANCE PAYLOAD REFERENCE
# =============================================================================

SUBDOMAIN_RECON_PAYLOAD_REFERENCE = """
## Subdomain Reconnaissance Reference

### Common subdomain wordlists

```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/altdns-words.txt
```

### Subdomain permutation patterns

```
{{word}}-dev, {{word}}-staging, {{word}}-test, {{word}}-prod
{{word}}1, {{word}}2, {{word}}01, {{word}}02
dev-{{word}}, staging-{{word}}, test-{{word}}
{{word}}-api, {{word}}-api-v1, {{word}}-api-v2
{{word}}-admin, {{word}}-portal, {{word}}-app
{{word}}-us, {{word}}-eu, {{word}}-asia
{{word}}-old, {{word}}-legacy, {{word}}-backup
```

### DNS record type quick reference

| Type | Purpose | Security Relevance |
|------|---------|-------------------|
| A | IPv4 address | Direct host targeting |
| AAAA | IPv6 address | Dual-stack exposure |
| CNAME | Alias | Takeover via dangling alias |
| MX | Mail server | Email infrastructure |
| NS | Nameserver | Zone transfer target |
| TXT | Text records | SPF, DMARC, verification tokens |
| SOA | Zone authority | DNS admin contact |
| DNSKEY | DNSSEC public key | Zone signing integrity |

### Cloud provider CNAME takeover indicators

| Provider | Dangling CNAME pattern | Takeover method |
|----------|----------------------|----------------|
| AWS S3 | s3.amazonaws.com | Create bucket matching name |
| CloudFront | cloudfront.net | Create CloudFront distribution |
| GitHub Pages | github.io | Push repo with matching name |
| Heroku | herokudns.com | Create Heroku app |
| Azure | azurewebsites.net | Create Azure web app |
| Google App Engine | appspot.com | Create App Engine app |
| Firebase | firebaseapp.com | Create Firebase project |
| Shopify | myshopify.com | Claim store name |
| Fastly | fastly.net | Create Fastly service |
| Tumblr | tumblr.com | Claim blog name |

### Resolver rate-limiting guidelines

- Public resolvers (8.8.8.8, 1.1.1.1): max 100 qps
- Internal resolvers: max 1000 qpm
- Use rotating resolver list to distribute load
- Add 50ms delay between batches if rate-limited
"""

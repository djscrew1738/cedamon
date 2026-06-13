"""
RedAmon Transport Security Assessment Prompts

Domain-wide TLS/SSL configuration, certificate chain, cipher suite,
and transport-layer security testing.

This skill is DISTINCT from:
- cve_exploit (tests specific CVEs, not configuration)
- attack_surface_mapping (includes TLS as one data point, not deep analysis)
- domain_takeover (DNS-level, not transport layer)
"""

# =============================================================================
# TRANSPORT SECURITY MAIN WORKFLOW
# =============================================================================

TRANSPORT_SECURITY_TOOLS = """
## ATTACK SKILL: TRANSPORT SECURITY ASSESSMENT

**CRITICAL: This attack skill has been CLASSIFIED as Transport Security Assessment.**
**You MUST follow the transport security workflow below.**

This skill covers SIX transport security pillars:
1. **TLS version and cipher suite analysis** — supported protocols, weak ciphers,
   deprecated algorithms (SSLv2, SSLv3, TLS 1.0/1.1, RC4, DES, MD5, SHA1)
2. **Certificate chain validation** — trust chain, expiration, revocation (CRL/OCSP),
   self-signed, wildcard abuse, name mismatch
3. **HSTS and security headers** — HSTS preload, max-age, includeSubDomains,
   certificate transparency expectations
4. **Downgrade and MITM attack vectors** — POODLE, BEAST, CRIME, BREACH,
   Sweet32, Logjam, FREAK, DROWN
5. **Certificate transparency and pinning** — CT log monitoring, HPKP (deprecated
   but assessed), Expect-CT, key pinning gaps
6. **Domain-wide TLS posture** — consistency across subdomains, mixed content,
   certificate sharing, SAN coverage gaps

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
TLS version scan enabled:         {tsa_tls_scan_enabled}
Cipher suite analysis enabled:    {tsa_cipher_enabled}
Certificate validation enabled:   {tsa_cert_validation_enabled}
HSTS header check enabled:        {tsa_hsts_enabled}
Downgrade test enabled:           {tsa_downgrade_enabled}
CT log monitoring enabled:        {tsa_ct_enabled}
Deep subdomain TLS scan:          {tsa_deep_scan_enabled}
Target domain:                    {tsa_target_domain}
```

**Hard rules:**
- If `Downgrade test enabled: False`, do NOT run POODLE/BEAST/CRIME/etc.
  Only report configuration findings.
- If `Deep subdomain TLS scan: False`, scan only the apex domain and
  www subdomain. Do not scan all discovered subdomains.
- NEVER downgrade a production server's TLS configuration. Read-only assessment only.
- Document every tested endpoint with exact hostname and port.

---

## MANDATORY TRANSPORT SECURITY WORKFLOW

### Step 1: Apex domain baseline (kali_shell / execute_curl)

Start with the target domain's primary HTTPS endpoint:

```
# testssl.sh deep scan (pre-installed in kali_shell)
kali_shell({{"command": "testssl --fast --color 0 <TARGET_DOMAIN>:443 > /tmp/testssl_apex.txt 2>&1"}})
# Quick TLS version probe
execute_curl({{"args": "-s -I --tlsv1.3 'https://<TARGET_DOMAIN>/'"}})
execute_curl({{"args": "-s -I --tlsv1.2 'https://<TARGET_DOMAIN>/'"}})
execute_curl({{"args": "-s -I --tlsv1.1 'https://<TARGET_DOMAIN>/'"}})
execute_curl({{"args": "-s -I --tlsv1.0 'https://<TARGET_DOMAIN>/'"}})
```

Capture: supported TLS versions, cipher suites, certificate details, HSTS header.

**After Step 1, request `transition_phase` to exploitation if active downgrade tests are authorized.**

### Step 2: Certificate chain analysis

```
# Full certificate chain
kali_shell({{"command": "openssl s_client -connect <TARGET_DOMAIN>:443 -servername <TARGET_DOMAIN> -showcerts </dev/null 2>/dev/null | openssl x509 -noout -text"}})
# OCSP check
kali_shell({{"command": "openssl s_client -connect <TARGET_DOMAIN>:443 -servername <TARGET_DOMAIN> -status </dev/null 2>/dev/null | grep -i 'ocsp response'"}})
# CRL check
kali_shell({{"command": "openssl x509 -in <(openssl s_client -connect <TARGET_DOMAIN>:443 -servername <TARGET_DOMAIN> </dev/null 2>/dev/null) -noout -text | grep -i 'crl distribution'"}})
# Certificate expiry
kali_shell({{"command": "echo | openssl s_client -connect <TARGET_DOMAIN>:443 -servername <TARGET_DOMAIN> 2>/dev/null | openssl x509 -noout -dates"}})
```

Look for:
- Self-signed or untrusted intermediate
- Expired or near-expiry certificates
- Weak signature algorithm (SHA1, MD5)
- Missing OCSP/CRL
- Wildcard cert without proper SAN coverage
- Name mismatch (CN/SAN doesn't match hostname)

### Step 3: Cipher suite grading

```
# testssl cipher analysis
kali_shell({{"command": "testssl -E --color 0 <TARGET_DOMAIN>:443 > /tmp/testssl_ciphers.txt 2>&1"}})
# Nmap cipher enumeration
execute_nmap({{"args": "--script ssl-enum-ciphers -p 443 <TARGET_DOMAIN>"}})
```

Flag weak ciphers:
- NULL, EXPORT, DES, 3DES, RC4
- CBC mode ciphers with TLS 1.0 (BEAST/POODLE risk)
- RSA key exchange (no forward secrecy)
- DH parameters < 2048 bits (Logjam)

### Step 4: HSTS and security headers

```
execute_curl({{"args": "-s -I 'https://<TARGET_DOMAIN>/'"}})
execute_curl({{"args": "-s -I 'http://<TARGET_DOMAIN>/'"}})
```

HSTS checklist:
- `Strict-Transport-Security` present on HTTPS?
- `max-age` >= 31536000 (1 year)?
- `includeSubDomains` present?
- `preload` present?
- HTTP -> HTTPS redirect with HSTS?
- Subdomains serving HTTPS without HSTS?

Also check:
- `Expect-CT` (certificate transparency enforcement)
- `Public-Key-Pins` (HPKP, deprecated but may still be configured)

### Step 5: Downgrade vulnerability testing (CONDITIONAL on `Downgrade test enabled`=True)

```
# SSLv2/SSLv3 test
kali_shell({{"command": "testssl -p --color 0 <TARGET_DOMAIN>:443 > /tmp/testssl_proto.txt 2>&1"}})
# POODLE (SSLv3)
kali_shell({{"command": "testssl -O --color 0 <TARGET_DOMAIN>:443"}})
# Heartbleed
kali_shell({{"command": "testssl -B --color 0 <TARGET_DOMAIN>:443"}})
# Logjam (weak DH)
kali_shell({{"command": "testssl -J --color 0 <TARGET_DOMAIN>:443"}})
# Sweet32 (64-bit block ciphers)
kali_shell({{"command": "testssl -W --color 0 <TARGET_DOMAIN>:443"}})
# ROBOT (RSA padding oracle)
kali_shell({{"command": "testssl -R --color 0 <TARGET_DOMAIN>:443"}})
```

### Step 6: Subdomain TLS consistency (CONDITIONAL on `Deep subdomain TLS scan`=True)

```
# Scan all discovered subdomains for TLS consistency
execute_httpx({{"args": "-l notes/subs.txt -tls-probe -silent -j -o notes/tls_probe.json"}})
# testssl on a sample of subdomains
kali_shell({{"command": "for sub in $(head -20 notes/subs.txt); do testssl --fast --color 0 $sub:443 > /tmp/testssl_$(echo $sub | tr '.' '_').txt 2>&1; done"}})
```

Look for:
- Subdomains with weaker TLS config than apex
- Self-signed certs on internal subdomains
- Mixed content (HTTP resources on HTTPS pages)
- Missing HSTS on some subdomains

### Step 7: Certificate transparency and revocation

```
# CT log search via crt.sh
execute_curl({{"args": "-s 'https://crt.sh/?q=%.<TARGET_DOMAIN>&output=json'"}})
# OCSP stapling check
kali_shell({{"command": "openssl s_client -connect <TARGET_DOMAIN>:443 -servername <TARGET_DOMAIN> -tlsextdebug </dev/null 2>&1 | grep -i 'ocsp response'"}})
```

### Step 8: Reporting requirements

The final report MUST contain:
- **TLS versions supported** (graded: A / B / C / F based on oldest version)
- **Cipher suite summary** (strong FS ciphers vs weak / deprecated ciphers)
- **Certificate details** (issuer, expiry, SAN list, signature algorithm, chain trust)
- **HSTS status** (present, max-age, includeSubDomains, preload, subdomain coverage)
- **Downgrade vulnerabilities** (POODLE, BEAST, CRIME, Logjam, Sweet32, ROBOT, Heartbleed)
- **Subdomain consistency** (weakest subdomain config, self-signed certs, mixed content)
- **CT/OCSP status** (transparency, stapling, revocation)
- **Remediation** (disable weak protocols/ciphers, enable HSTS with preload,
  fix certificate chain, enable OCSP stapling, patch known CVEs)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | TLS configuration enumerated (versions, ciphers, cert chain) | INFORMATIONAL |
| 2 | Weak configuration identified (TLS 1.0, RC4, SHA1 cert, no HSTS) | POTENTIAL |
| 3 | Downgrade vulnerability confirmed (POODLE, Logjam, Sweet32) | EXPLOITED |
| 4 | Heartbleed/ROBOT with data extraction, or full MITM feasible | EXPLOITED (CRITICAL) |
"""


# =============================================================================
# TRANSPORT SECURITY PAYLOAD REFERENCE
# =============================================================================

TRANSPORT_SECURITY_PAYLOAD_REFERENCE = """
## Transport Security Reference

### TLS version grading

| Grade | Supported versions | Risk |
|-------|-------------------|------|
| A | TLS 1.2+ only, no weak ciphers | Low |
| B | TLS 1.2 primary, TLS 1.1 fallback | Medium |
| C | TLS 1.0+ supported | High |
| F | SSLv3 or SSLv2 supported | Critical |

### Cipher suite flags (testssl output)

| Flag | Meaning |
|------|---------|
| `Forward Secrecy` | Ephemeral key exchange (ECDHE/DHE) |
| `AEAD` | Authenticated encryption (AES-GCM, ChaCha20) |
| `RC4` | Broken stream cipher |
| `CBC` | Vulnerable to padding oracle attacks |
| `NULL` | No encryption |
| `EXPORT` | Weakened ciphers (FREAK/Logjam) |

### HSTS baseline configuration

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Checklist:
- [ ] Present on ALL HTTPS responses
- [ ] max-age >= 31536000
- [ ] includeSubDomains for wildcard coverage
- [ ] preload for HSTS preload list
- [ ] HTTP redirects to HTTPS with 301
- [ ] No HTTP-accessible content on sensitive paths

### Known downgrade CVE quick reference

| CVE | Attack | Condition | Test |
|-----|--------|-----------|------|
| CVE-2014-0160 | Heartbleed | OpenSSL 1.0.1 | `testssl -B` |
| CVE-2014-3566 | POODLE | SSLv3 + CBC | `testssl -O` |
| CVE-2015-0204 | FREAK | EXPORT RSA ciphers | `testssl -F` |
| CVE-2015-4000 | Logjam | DH < 2048 bits | `testssl -J` |
| CVE-2016-0703 | DROWN | SSLv2 export ciphers | `testssl -D` |
| CVE-2016-2183 | Sweet32 | 64-bit block ciphers | `testssl -W` |
| CVE-2016-9244 | Ticketbleed | F5 BIG-IP | `testssl -T` |
| CVE-2017-17428 | ROBOT | RSA key exchange | `testssl -R` |
| CVE-2018-0732 | Bleichenbacher | RSA padding oracle | `testssl -R` |

### Certificate SAN coverage checklist

- [ ] Apex domain covered
- [ ] www subdomain covered
- [ ] All public subdomains covered (or wildcard used)
- [ ] Wildcard cert covers one level only (*.example.com does NOT cover a.b.example.com)
- [ ] No internal/private names in public cert
- [ ] No IP addresses in SAN unless specifically needed
"""

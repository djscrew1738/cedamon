---
name: Amass
description: Deep subdomain enumeration and network mapping using DNS, certificates, APIs, and web crawling with OWASP Amass
---

# Amass

Pull this skill for comprehensive subdomain enumeration and mapping of an organisation's external attack surface. Amass integrates with dozens of data sources (CRT.sh, Shodan, VirusTotal, etc.) and uses graph analysis to discover relationships between domains.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Subdomain enumeration (full) | `execute_amass` | Primary interface — DNS + API + crawler |
| Subdomain brute-force | `execute_amass` | `-brute` flag with optional wordlist |
| Passive enumeration only | `execute_amass` | `-passive` — no direct DNS queries |
| Intel (domain discovery) | `execute_amass` | `intel` subcommand — find root domains |
| Visualise results | `execute_amass` | `-viz` — D3.js HTML graph |
| DB interaction | `execute_amass` | `db` subcommand — query local DB |
| Track changes over time | `execute_amass` | Compare multiple scan runs |

## Primer

Amass works in three phases:
1. **Data gathering** — pulls from 50+ sources (APIs, web scraping, cert transparency, DNS)
2. **Brute forcing** — optionally fuzzes subdomains from a wordlist
3. **Graph analysis** — correlates results and visualises the domain relationship graph

The tool stores results in a local graph database (`~/.local/share/amass/`), enabling cross-session queries and incremental scanning.

## Enumeration modes

### Passive (fastest, no direct traffic to target)
```bash
execute_amass enum -passive -d example.com -o subs.txt
```

### Default (DNS + APIs + web crawler)
```bash
execute_amass enum -d example.com -o subs.txt
```

### With brute-force (most thorough)
```bash
execute_amass enum -brute -d example.com -w /wordlists/subdomains-top1million-5000.txt -o subs.txt
```

### Recursive (enum per subdomain found)
```bash
execute_amass enum -d example.com -o subs.txt -r
```

### Config-driven (custom API keys)
```bash
execute_amass enum -d example.com -config /path/to/config.ini
```

### Multiple domains at once
```bash
execute_amass enum -d example.com -d example.org -d example.net -o subs.txt
```

## Intel subcommand (find root domains)

Use when you have an ASN, company name, or IP range and need to discover domains.

```bash
# Find domains by company name
execute_amass intel -org "Example Corp" -o domains.txt

# Find domains hosted on an ASN
execute_amass intel -asn 12345 -o domains.txt

# Reverse DNS on CIDR range
execute_amass intel -cidr 203.0.113.0/24 -o domains.txt
```

## Output format options

| Flag | Format | Use case |
|------|--------|----------|
| `-o subs.txt` | One FQDN per line | Pipeline input to httpx/nuclei |
| `-o json` | JSON lines | Programmatic processing |
| `-o csv` | CSV | Spreadsheet ingestion |
| `-oA subs` | All formats (txt/json/csv) | Comprehensive logging |
| `-viz` | D3.js HTML | Visual presentation |

## Key flags

| Flag | Purpose |
|------|---------|
| `-d` | Domain to enumerate |
| `-passive` | No direct DNS queries; API data only |
| `-brute` | Enable subdomain brute-forcing |
| `-w` | Wordlist path (requires `-brute`) |
| `-r` | Recursive — sub-subdomain enumeration |
| `-config` | Custom config with API keys |
| `-o` | Output file path |
| `-json` | JSON output directory |
| `-nf` | Netblock filter — ignore IPs in this range |
| `-asn` | Filter results to specific ASN |
| `-max-dns-queries` | Rate-limit DNS queries |
| `-timeout` | Per-source timeout |
| `-include-unresolved` | Include names that didn't resolve |

## Enrichment workflow

```bash
# 1. Passive recon (fast)
execute_amass enum -passive -d example.com -o passive.txt

# 2. Full recon (slower, deeper)
execute_amass enum -d example.com -o all.txt

# 3. Full + brute-force (deepest)
execute_amass enum -brute -d example.com -w /wordlists/subdomains-top1million-5000.txt -o full.txt

# 4. Pipe to httpx for live probing
execute_amass enum -passive -d example.com -o - | execute_httpx -silent -o live.txt
```

## Performance tuning

| Scenario | Approach |
|----------|----------|
| Quick check (5 min) | `-passive` only |
| Standard engagement | Default enum (no brute) |
| Deep dive | `-brute -w big.txt -r` |
| Rate-limited target | `-max-dns-queries 50` |
| Large scope (100+ domains) | `-passive` followed by targeted brute on interesting subdomains |

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| API rate limits | Add more API keys in config.ini; use `-timeout` to rotate faster |
| Too many results from wildcards | Use `-nf` to filter known wildcard netblocks |
| Amass DB corruption | `rm -rf ~/.local/share/amass/` and re-run |
| False positives | Pipe through `execute_httpx -silent -mc 200,301,302,401,403` to filter live hosts |
| Outdated config | Check `amass -config` points to the latest `config.ini` with valid API keys |

## Hand-off

- After finding subdomains: `-> /skill/tooling/httpx` to probe for live HTTP services
- For port scanning discovered hosts: `-> /skill/tooling/naabu`
- For crawling discovered endpoints: `-> /skill/tooling/katana`
- For template-based scanning: `-> /skill/tooling/nuclei`
- For gathering historical URLs: `-> /skill/tooling/gau`

## Pro tips

- **API keys matter**: Amass with default config uses only OSS sources (~20). Adding VirusTotal, Shodan, SecurityTrails, and AlienVault OTX keys activates 50+ sources and dramatically improves coverage.
- **Start passive, add brute later**: Passive runs complete in minutes. Only add `-brute` after reviewing passive results — brute-force can take hours for large wordlists.
- **Use `-o -` for piping**: Amass can output to stdout (`-o -`), making it chainable with `execute_httpx`, `execute_katana`, etc. without intermediate files.
- **Incremental scanning**: Amass stores everything in its graph DB. Running the same domain again adds new results without duplicating existing ones — ideal for continuous monitoring.
- **The `intel` subcommand is gold**: Feed it an ASN or CIDR to discover domains you didn't know belonged to the target. This often reveals forgotten subsidiaries and dev environments.

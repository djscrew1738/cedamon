---
name: Gau & Wayback Machine
description: Gather historical URLs from Wayback Machine, AlienVault OTX, and CommonCrawl using gau for recon and endpoint discovery
---

# Gau & Wayback Machine

Pull this skill to collect every URL the target has ever exposed — historical endpoints, JS files, parameters, and sensitive paths — from Wayback Machine, AlienVault OTX, and CommonCrawl archives.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| URL gathering (single domain) | `execute_gau` | Primary interface |
| URL gathering (many domains) | `execute_gau` | Pipe domains via stdin |
| Filter by status code | `execute_gau` | Internal filtering (limited) |
| Get URLs for specific subdomain | `execute_gau` | Supports subdomain.mode |
| Get all subs URLs at once | `execute_gau` | Subdomain mode with `--subs` |
| Extract only parameters | `execute_gau` + grep | Filter for `?` or `=` in output |

## Primer

Archived URLs reveal:
- **Forgotten endpoints** — old API versions (`/api/v1`), dev portals, test consoles
- **Exposed parameters** — know what params the app accepts for fuzzing
- **JS files** — source maps, API routes, hardcoded secrets
- **Sensitive paths** — admin panels, config files, backup files
- **Historical vulnerabilities** — endpoints that were once vulnerable (and may still be)

## Basic usage

```bash
# Get all URLs for a domain
execute_gau example.com

# With subdomains
execute_gau --subs example.com

# Output to file
execute_gau --subs example.com > urls.txt

# Multiple domains (stdin)
echo -e "example.com\nexample.org" | execute_gau --subs

# From file
cat domains.txt | execute_gau --subs
```

## Filtering and processing

```bash
# Extract URLs with parameters (for parameter fuzzing)
execute_gau --subs example.com | grep -E '\?[a-z]+=' > param_urls.txt

# Extract JS files
execute_gau --subs example.com | grep -E '\.js($|\?)' > js_files.txt

# Extract PDFs, JSON, XML (potential document disclosure)
execute_gau --subs example.com | grep -E '\.(pdf|json|xml|csv|xls|doc)' > docs.txt

# Find potential SSRF parameters
execute_gau --subs example.com | grep -E '(url=|redirect=|return=|next=|load=)' > ssrf_params.txt

# Filter for interesting response codes via httpx
execute_gau --subs example.com | execute_httpx -silent -mc 200,301,302 -o live_paths.txt
```

## Key flags

| Flag | Purpose |
|------|---------|
| `--subs` | Include subdomains |
| `--blacklist` | Exclude extensions (e.g., `--blacklist png,jpg,gif,css`) |
| `--o` | Output file |
| `--from` | Date-based filter (e.g., `--from 2023-01-01`) |
| `--to` | End date for date range |
| `--fc` | Filter by status code (e.g., `--fc 404,302`) |
| `--cc` | Max concurrent connections |

## Advanced filter chains

```bash
# Remove noise (images, fonts, stylesheets)
execute_gau --subs example.com | grep -vE '\.(png|jpg|jpeg|gif|css|ico|svg|woff|ttf|eot)$'

# Focus on endpoints with interesting keywords
execute_gau --subs example.com | grep -iE '(admin|api|dev|test|staging|beta|debug|config|backup|internal)'

# Extract unique parameter names
execute_gau --subs example.com | grep -oP '\?[\w=&]+' | tr '&' '\n' | grep -oP '^[^=]+' | sort -u > param_names.txt

# Find potential SQL injection points
execute_gau --subs example.com | grep -iE '(id=|page=|pid=|uid=|user=|order=|query=)' | grep -vE '\.(css|js|png|jpg)' > sqli_params.txt
```

## Integration with other tools

```bash
# gau → httpx → katana (full discovery pipeline)
execute_gau --subs example.com | \
  execute_httpx -silent -mc 200,301,302 -o live.txt && \
  execute_katana -list live.txt -jc -o crawled.txt

# gau → URL dedup → ffuf (parameter fuzzing)
execute_gau --subs example.com | grep '?id=' | sort -u | \
  xargs -I@ execute_ffuf -u @FUZZ -w params.txt -mc 200

# gau → nuclei (historical endpoint scanning)
execute_gau --subs example.com > all.txt
execute_nuclei -l all.txt -t ~/nuclei-templates/ -o nuclei_historical.txt
```

## What to look for

| Pattern | Potential issue |
|---------|----------------|
| `/api/` endpoints | API access without auth |
| `?debug=true` | Debug mode in production |
| `.git/config` | Source code disclosure |
| `.env` | Environment variables (secrets) |
| `swagger.json` or `openapi.json` | API spec disclosure |
| `s3://` or `aws_access_key` | Cloud credential leaks in JS |
| `redirect=` or `url=` | Open redirect / SSRF |
| `callback=` or `jsonp=` | JSONP/CSRF |
| `admin` or `console` | Admin interface exposure |
| `Internal-IP` in response headers | Internal network disclosure |

## Recovery

| Problem | Fix |
|---------|-----|
| Too many results | Add filters early; start with specific subdomains |
| Rate-limited | Add delay between queries; use `--cc 1` |
| Missing expected results | Use `--subs` flag; try from another network/VPN |
| Wayback results stale | Combine with live crawling (`execute_katana`) for current data |

## Hand-off

- After gathering URLs: `-> /skill/tooling/ffuf` for parameter fuzzing
- For JS analysis: `-> /skill/tooling/jsluice` to extract endpoints and secrets
- For crawling live endpoints: `-> /skill/tooling/katana`
- For scanning discovered paths: `-> /skill/tooling/nuclei`
- For finding interesting endpoints: `-> /skill/vulnerabilities/xss_discovery` or `-> /skill/vulnerabilities/open_redirect`
- For deep subdomain enumeration: `-> /skill/tooling/amass`

## Pro tips

- **Always use `--subs`**: omitting it only gets URLs for the bare domain. You'll miss most of the attack surface.
- **Filter early**: A single domain can yield 100K+ URLs. Pipe through grep immediately to keep output manageable.
- **Date range for active targets**: Use `--from 2024-01-01` for recently-discovered targets; older URLs may point to deprecated (but less monitored) endpoints.
- **Blacklist media**: `--blacklist png,jpg,gif,css,svg,ico,woff,ttf` removes most noise automatically.
- **gau, then crawl, then fuzz**: The most effective pipeline is gau for historical URLs → katana for live crawling → ffuf for parameter discovery. Each tool fills gaps the other misses.

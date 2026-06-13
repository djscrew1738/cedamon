---
name: WPScan
description: WordPress security scanner for plugin/theme enumeration, vulnerability detection, user enumeration, and brute-force attacks
---

# WPScan

Pull this skill when you've identified a WordPress site and need to enumerate its plugins, themes, users, and known vulnerabilities. WPScan is the de-facto WordPress security assessment tool.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Basic WP enumeration | `execute_wpscan` | Plugins, themes, users |
| Vulnerability scanning | `execute_wpscan` | With WPScan API token |
| User enumeration | `execute_wpscan` | `--enumerate u` |
| Plugin discovery | `execute_wpscan` | `--enumerate vp` (vulnerable plugins) |
| Brute-force | `execute_wpscan` | `--passwords` on found users |
| Aggressive mode | `execute_wpscan` | `--plugins-detection aggressive` |
| Output to file | `execute_wpscan` | `-o` flag |

## Primer

WPScan enumerates four key areas:
1. **Plugins** — including version and known vulnerabilities (with API token)
2. **Themes** — including version and known vulnerabilities
3. **Users** — usernames from author archives, posts, and API endpoints
4. **Timthumb** — deprecated timthumb.php files with known issues

The WPScan Vulnerability Database API (free token via wpscan.com/register) provides accurate CVE-to-plugin/theme mapping.

## Basic enumeration

```bash
# Minimal — just check if it's WordPress
execute_wpscan --url https://target.com

# Full enumeration (no API token)
execute_wpscan --url https://target.com --enumerate vp,vt,u

# With API token (vulnerability data)
execute_wpscan --url https://target.com --api-token YOUR_TOKEN --enumerate vp,vt,u

# Output to file
execute_wpscan --url https://target.com --api-token YOUR_TOKEN \
  --enumerate vp,vt,u --output wpscan_report.txt
```

## Enumeration flags

| Flag | Purpose |
|------|---------|
| `--enumerate vp` | Vulnerable plugins only |
| `--enumerate vt` | All plugins (including non-vulnerable) |
| `--enumerate ap` | All plugins (aggressive) |
| `--enumerate u` | Usernames (1-10 by default) |
| `--enumerate u1-100` | Username range |
| `--enumerate t` | Themes |
| `--enumerate tt` | Timthumb files |
| `--enumerate cb` | Config backups |
| `--enumerate dbe` | Database exports |
| `--enumerate m` | Media (attachment IDs) |

## Detection modes

| Mode | Speed | Reliability |
|------|-------|-------------|
| `passive` | Fastest | Low (only checks response content) |
| `mixed` (default) | Moderate | Medium |
| `aggressive` | Slow | High (sends direct requests) |

```bash
# Fast passive scan (broad overview)
execute_wpscan --url https://target.com --enumerate vp,u --plugins-detection passive

# Aggressive (thorough)
execute_wpscan --url https://target.com --enumerate vp,vt,ap,u,t --plugins-detection aggressive
```

## Brute-force

```bash
# Brute-force found users
execute_wpscan --url https://target.com --passwords rockyou.txt

# Specific user
execute_wpscan --url https://target.com --usernames admin --passwords passwords.txt

# Multi-user brute with throttling
execute_wpscan --url https://target.com --passwords rockyou.txt --max-threads 5
```

## Recipes

### Full audit pipeline
```bash
# Step 1: Basic check + API token for vuln data
execute_wpscan --url https://target.com --api-token $WPSCAN_TOKEN \
  --enumerate vp,vt,u,t,cb,dbe \
  --plugins-detection aggressive \
  -o wpscan_full.txt

# Step 2: Check for XML-RPC (common attack vector)
execute_curl -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'

# Step 3: If XML-RPC enabled, test credentials via wp.getUsersBlogs
execute_curl -X POST https://target.com/xmlrpc.php \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password</value></param></params></methodCall>'
```

### Post-exploitation: config file check
```bash
# Common WordPress config file paths
for path in wp-config.php wp-config-backup.txt wp-config.old wp-config.save \
            wp-config.php.bak wp-config.php.old wp-config.php~ .wp-config.php.swp; do
  execute_curl -s -o /dev/null -w "%{http_code}" "https://target.com/$path"
done
```

## Key WordPress paths

| Path | Purpose |
|------|---------|
| `/wp-admin/` | Admin login |
| `/wp-login.php` | Alternate login |
| `/xmlrpc.php` | XML-RPC API (brute-force, pingback) |
| `/wp-json/` | REST API |
| `/wp-content/` | Content directory |
| `/wp-content/uploads/` | Uploaded files |
| `/wp-content/plugins/` | Plugin files |
| `/wp-content/themes/` | Theme files |
| `/wp-includes/` | Core includes |
| `/readme.html` | Version disclosure |
| `/wp-config.php~` | Config backup |
| `/.htaccess` | Access rules |

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| WPScan blocked by WAF | Use `--random-user-agent` and/or route through proxy |
| No API token = no vulns | Register at wpscan.com for a free API token |
| User enumeration blocked (author archives 404) | Use `--enumerate u` with WP JSON API: `wp-json/wp/v2/users` |
| False plugins detected | Passive mode may misidentify themes as plugins. Rerun with aggressive. |
| Results rate-limited | Use `--max-threads 1` and `--throttle` between requests |
| XML-RPC disabled | 405 Method Not Allowed = disabled. No brute-force via XML-RPC possible. |

## Detection avoidance

| Signal | Mitigation |
|--------|------------|
| Multiple 404s from plugin checks | Use passive mode — no direct plugin path requests |
| High request rate to wp-admin | Use `--throttle 2000` (2 second delay) |
| User enumeration via REST API | Check if `wp-json/wp/v2/users` returns data — this is the most common and quietest enumeration method |
| XML-RPC brute force in logs | Hard to avoid. Consider hydra against wp-login.php instead |

## Hand-off

- After finding vulnerable plugins: `-> /skill/tooling/nuclei` for CVE scanning
- After finding admin credentials: Log into wp-admin and look for RCE via theme/plugin editing or file upload
- For WordPress-specific CVEs: Check plugin names against known exploits
- For REST API endpoints discovered: `-> /skill/tooling/ffuf` for endpoint fuzzing
- After compromising WordPress: Check wp-config.php for database credentials and AWS keys

## Pro tips

- **Get the API token**: Without a token, WPScan won't tell you which plugins are vulnerable. Register at wpscan.com — the free tier gives 50 API requests per day.
- **Redundant user enumeration**: If author archives are disabled, try `wp-json/wp/v2/users`, `?author=1` redirects, or comment authors (if comments are open).
- **Version detection via readme.html**: If WPScan can't detect the WP version, check `/readme.html` — it displays the version in the HTML title.
- **Focus on vulnerable plugins**: The `--enumerate vp` flag is the highest-value output. A single vulnerable plugin with a public PoC is often all you need for RCE.
- **XML-RPC is the gift that keeps giving**: If XML-RPC is enabled and WPScan user enumeration works, you can brute-force 1000+ passwords per request using `system.multicall`. This is much faster than wp-login brute-force.

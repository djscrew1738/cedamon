---
name: Arjun
description: HTTP parameter discovery tool that finds hidden GET/POST parameters on web endpoints using heuristic scanning
---

# Arjun

Pull this skill when you need to discover undocumented or hidden HTTP parameters on web endpoints. Arjun uses a wordlist and heuristics to find parameters that the application accepts but doesn't advertise — often leading to hidden functionality or vulnerabilities.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Find GET parameters | `execute_arjun` | Default mode |
| Find POST parameters | `execute_arjun` | `--method POST` |
| Scan single URL | `execute_arjun` | `-u` flag |
| Scan from list | `execute_arjun` | `-i` for bulk |
| High-speed mode | `execute_arjun` | `--passive` first, then `--stable` |

## Primer

Arjun works by sending requests with potential parameters and measuring response size/timing differences. When adding a valid parameter changes the response (size, status code, or content), Arjun flags it as discovered.

**Why find hidden parameters:**
- Parameter-based access control (`?admin=true`, `?role=user`)
- Debug parameters (`?debug=1`, `?source=1`)
- API version overrides (`?v=2`, `?api=beta`)
- Internal IDs (`?user_id=`, `?order_id=`)
- Feature flags (`?feature=new_checkout`)

## Basic usage

```bash
# Single URL (GET)
execute_arjun -u https://target.com/api/endpoint

# With custom wordlist
execute_arjun -u https://target.com/api/endpoint -w /custom/params.txt

# POST method
execute_arjun -u https://target.com/api/login --method POST

# POST with body content type JSON
execute_arjun -u https://target.com/api/data --method POST --headers 'Content-Type: application/json'
```

## Key flags

| Flag | Purpose |
|------|---------|
| `-u` | Target URL |
| `-i` | Input file with multiple URLs |
| `-w` | Custom wordlist path |
| `--method` | HTTP method (`GET`, `POST`, `JSON` |
| `--headers` | Custom request headers |
| `-oT` | Output format (json, json_lines) |
| `-o` | Output file |
| `--stable` | More stable results (slower) |
| `--passive` | Only passive sources, no live scanning |
| `--include-similar` | Include responses with similar size |

## Recipes

### Scan endpoints from httpx output
```bash
# Find live endpoints first
execute_httpx -l urls.txt -silent -mc 200 | \
  xargs -I@ execute_arjun -u @ -o json > arjun_results.json
```

### POST parameter discovery with auth
```bash
execute_arjun -u https://target.com/api/update_profile \
  --method POST \
  --headers 'Authorization: Bearer eyJ...' \
  -o params.txt
```

### Bulk scan from file
```bash
execute_arjun -i endpoints.txt -o ../output/arjun_bulk.json
```

### Passive only (no requests to the target)
```bash
execute_arjun -u https://target.com/api/endpoint --passive
```

## What to do with discovered parameters

| If the parameter is... | Then check for... |
|------------------------|-------------------|
| `?debug=true` or `?debug=1` | Error stack traces, verbose logging |
| `?admin=true` or `?role=admin` | Privilege escalation via parameter pollution |
| `?id=X` or `?user_id=X` | IDOR — try other users' IDs |
| `?callback=X` or `?jsonp=X` | JSONP hijacking, XSS |
| `?redirect=X` or `?url=X` | Open redirect, SSRF |
| `?file=X` or `?page=X` | Path traversal, LFI |
| `?token=X` | Token reuse, token validation bypass |
| `?format=json` or `?format=xml` | XXE, content injection |
| `?signature=X` | Signature validation bypass |
| `?api_key=X` | API key disclosure in client-side code |

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| No parameters found | Try a larger wordlist; check if the endpoint responds at all |
| False positives (rate limiting) | The app may return "rate limit" pages that look like different responses. Use `--stable`. |
| Too many requests blocked | Add delays or use `--stable` mode (slower but gentler) |
| Parameters found but not usable | Some parameters are read-only. Test if you can also *write* the parameter. |
| JSON API not responding | Use `--method JSON` and set `Content-Type: application/json` header |

## Hand-off

- After finding parameters: `-> /skill/tooling/ffuf` for value fuzzing on discovered params
- For IDOR testing on discovered ID params: `-> /skill/vulnerabilities/ssrf_idor`
- For LFI via discovered file params: `-> /skill/vulnerabilities/lfi_rfi`
- For XSS on discovered params: `-> /skill/vulnerabilities/xss_discovery`
- For scanning with discovered params: `-> /skill/tooling/nuclei` with custom templates

## Pro tips

- **Start with passive mode**: `--passive` checks Wayback Machine and other sources for known parameters before hitting the live server. This gives you results instantly and costs nothing.
- **Combine with gau**: Run `execute_gau --subs target.com | grep '?'` to find already-known parameters, then use Arjun to discover the hidden ones.
- **Content-type matters**: If the API expects JSON, Arjun's default GET requests may not find anything. Always match the API's expected content type.
- **Wordlist quality > wordlist size**: A curated list of 500 common parameters (debug, test, admin, token, api, etc.) often outperforms a generic 10K wordlist because it triggers meaningful functionality changes.
- **Look for response size deltas**: When reviewing results, focus on parameters that cause a unique change in response size (not just a 2KB standard increase). Large or unique changes are more likely to be functional than noise.

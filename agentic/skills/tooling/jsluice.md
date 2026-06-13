---
name: JSLuice
description: JavaScript analysis tool that extracts endpoints, secrets, and API routes from JavaScript files for bug bounty and security testing
---

# JSLuice

Pull this skill when you've collected JavaScript files from a target and need to extract API endpoints, hardcoded secrets, and interesting patterns. JSLuice parses JS files syntactically (not just regex) to find URLs, API routes, secret keys, and other high-value targets.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Extract endpoints | `execute_jsluice` | URLs and API routes from JS |
| Extract secrets | `execute_jsluice` | Hardcoded keys, tokens |
| Extract URLs | `execute_jsluice` | All URLs in JS files |
| Burp-style output | `execute_jsluice` | Host/endpoint pairs for scanning |
| Single file analysis | `execute_jsluice` | `url` subcommand for one JS file |
| Bulk analysis | `execute_jsluice` | Pipe via stdin multiple files |

## Primer

JavaScript files in modern webapps contain a wealth of undiscovered endpoints:
- API route paths (`/api/v2/users/:id`, `/graphql`)
- AWS/GCP/Azure access keys (accidentally committed)
- Firebase URLs, API tokens, and OAuth client IDs
- Internal hostnames and service endpoints
- Feature-flagged functionality (unreleased endpoints)
- Source map references and debug endpoints

## Basic usage

```bash
# Analyse a single JS file URL
execute_jsluice url https://target.com/assets/app.abc123.js

# Analyse a JS file and output all endpoints
execute_jsluice url https://target.com/assets/app.js --endpoints

# Analyse and output secrets
execute_jsluice url https://target.com/assets/app.js --secrets

# Output as URLs (ready for scanning)
execute_jsluice url https://target.com/assets/app.js --urls
```

## Key options

| Flag | Purpose |
|------|---------|
| `--endpoints` | Extract API routes and paths |
| `--secrets` | Extract hardcoded secrets and keys |
| `--urls` | Extract all discoverable URLs |
| `--burp` | Output in Burp-compatible format |
| `--depth` | JS parsing depth (for nested analysis) |
| `--no-color` | Plain output (for piping) |

## Recipes

### Full JS analysis pipeline
```bash
# 1. Gather JS files from Wayback and Katana
execute_gau --subs target.com | grep -E '\.js($|\?)' > js_candidates.txt
execute_katana -u https://target.com -jc >> js_candidates.txt

# 2. Remove duplicates
sort -u js_candidates.txt > js_files.txt

# 3. Run JSLuice on all files
while read url; do
  execute_jsluice url "$url" --urls >> all_endpoints.txt
  execute_jsluice url "$url" --secrets >> all_secrets.txt
done < js_files.txt

# 4. Probe discovered endpoints
sort -u all_endpoints.txt | execute_httpx -silent -mc 200,301,302,401,403 -o live.txt
```

### Scan JS from httpx-discovered source maps
```bash
execute_katana -u https://target.com -jc -d 2 | \
  grep -E '\.map($|\?)' | \
  sed 's/\.map//' | \
  while read url; do execute_jsluice url "$url" --endpoints; done
```

### Find Firebase URLs in JS
```bash
execute_jsluice url https://target.com/app.js | grep -i "firebaseio\|firestore\|firebaseapp"
```

### Extract API routes for target fuzzing
```bash
execute_jsluice url https://target.com/app.js --burp | sort -u > api_routes.txt
# Now feed these to ffuf for path fuzzing
execute_ffuf -w api_routes.txt -u https://target.com/FUZZ -mc 200,401,403,500
```

## What to look for

| Pattern | Potentially contains |
|---------|---------------------|
| `https://*.firebaseio.com` | Unsecured Firebase DB |
| `https://s3.*.amazonaws.com` | Public S3 bucket |
| `AKIA[0-9A-Z]{16}` | AWS Access Key ID |
| `-----BEGIN.*PRIVATE KEY-----` | Private key material |
| `https://*.cloudfront.net` | CloudFront distribution |
| `api_key=`, `apiKey=` | API keys for third-party services |
| `wss://` or `ws://` | WebSocket endpoints |
| `graphql` | GraphQL API |
| `internal`, `staging`, `dev` | Unreleased/less-secure endpoints |
| `sourceMappingURL` | Source map reference |
| `oauth`, `client_id` | OAuth application credentials |

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| Minified JS not parseable | JSLuice handles most minified JS, but heavily obfuscated code may need `--depth` increased |
| Too many results from large JS | Filter with grep immediately; focus on `--secrets` and `--endpoints` flags |
| JS file 404s | Wayback may have stale URLs. Always run `execute_httpx` first to confirm JS files are live |
| Source maps don't load | Check `--depth` flag; some maps reference other maps recursively |
| False positive secrets | Not every string matching a regex is a real secret. Verify AWS keys with `execute_code` calling the IAM API |

## Hand-off

- After finding endpoints in JS: `-> /skill/tooling/katana` to crawl discovered paths
- For fuzzing discovered API routes: `-> /skill/tooling/ffuf`
- For AWS keys found in JS: `-> /skill/cloud/aws`
- For Firebase URLs: `-> /skill/technologies/firebase_firestore`
- For API scanning: `-> /skill/api_security/openapi_swagger_exposure`

## Pro tips

- **JS are gold mines**: Modern SPAs (React, Angular, Vue) bundle all their frontend logic into JS files, including API endpoints hidden behind dynamic imports. Spend time on JS analysis.
- **Check source maps**: If source maps are exposed (`app.js.map`), you get the original, readable source code. Load `app.js` → find `sourceMappingURL` → fetch the `.map` file → run JSLuice on the expanded source.
- **Combine with gau for historical JS**: Old versions of JS files (from Wayback Machine) may contain endpoints that have been removed from the current version. These old endpoints are often still functional on the backend.
- **Focus on bundled chunks**: Webpack/vite chunks like `vendor.abc123.js`, `pages/Login.abc123.js`, or `chunk-*.js` often contain route-specific API calls that don't appear in the main bundle.
- **Not just URLs — look for patterns**: JSLuice's `--secrets` mode finds things like `STRIPE_PUBLIC_KEY`, `FIREBASE_API_KEY`, `GOOGLE_MAPS_KEY`, and `SENTRY_DSN`. These can unlock API access or information leakage.

---
name: Playwright
description: Browser automation for authenticated scanning, dynamic page analysis, JavaScript-heavy application testing, and screenshot capture
---

# Playwright

Pull this skill when you need to interact with JavaScript-heavy web applications that require browser rendering — SPAs, login-gated pages, dynamic content that curl/httpx can't see, or when you need authenticated screenshots.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Navigate to URL | `execute_playwright` | Render JS-heavy pages |
| Screenshot capture | `execute_playwright` | Visual evidence of findings |
| Extract page content | `execute_playwright` | Get rendered HTML/DOM |
| Fill forms & login | `execute_playwright` | Authenticated page access |
| Click & interact | `execute_playwright` | Trigger JS events |
| Extract links | `execute_playwright` | Get all hrefs from rendered page |
| Browser console logs | `execute_playwright` | Read JS console output |
| Cookie management | `execute_playwright` | Save/restore auth state |

## Primer

Playwright uses a headless (or headed) Chromium browser to render pages exactly as a user would see them. This reveals:

- **SPA content** — React, Vue, Angular pages that load content via XHR
- **Login-gated content** — pages behind authentication (after providing cookies)
- **JavaScript-dependent vulnerabilities** — DOM-based XSS, client-side injection
- **Captured network requests** — all API calls the page makes during load
- **Visual evidence** — screenshots for reports and findings

## Basic usage

```bash
# Navigate and capture page content
execute_playwright https://target.com/login

# Take a screenshot
execute_playwright https://target.com --screenshot login_page.png

# Extract all links from rendered page
execute_playwright https://target.com --action extract-links

# Get console logs
execute_playwright https://target.com --action console-logs
```

## Authentication workflows

### Cookie-based auth
```bash
# Step 1: Get session cookies (via login form)
execute_playwright https://target.com/login --action login \
  --user "admin" --pass "Password123"

# Step 2: Access authenticated pages
execute_playwright https://target.com/admin/dashboard --cookies session.json
```

### Save and reuse auth state
```bash
# First run: capture auth state
execute_playwright https://target.com/login \
  --action login \
  --user "admin" \
  --pass "Password123" \
  --save-state auth_state.json

# Subsequent runs: reuse auth state
execute_playwright https://target.com/admin --state auth_state.json
```

## Recipes

### Screenshot a list of URLs
```bash
# Take screenshots of all live hosts
execute_playwright https://target.com --screenshot target_homepage.png

# Then do it for subpages
for path in /admin /api /login /dashboard; do
  execute_playwright "https://target.com$path" --screenshot "page_${path//\//_}.png"
done
```

### Extract API calls from a SPA
```bash
# Navigate the app as a user and capture all XHR requests
execute_playwright https://target.com/app --action network-log \
  --timeout 30000

# This reveals all API endpoints, GraphQL queries, and XHR calls
# that the SPA makes during load
```

### Fill forms dynamically
```bash
# Test form validation
execute_playwright https://target.com/register \
  --form '{"email":"test@test.com","password":"Test123!","confirm":"Test123!"}'

# Check if any hidden fields are injected (like CSRF tokens)
```

### Test for DOM XSS
```bash
# Navigate to page with payload in URL
execute_playwright "https://target.com/search?q=<img src=x onerror=alert(1)>" \
  --action evaluate "alert('XSS')"
```

## Key options

| Option | Purpose |
|--------|---------|
| `--screenshot` | Save screenshot to file |
| `--action` | `login`, `extract-links`, `console-logs`, `network-log`, `screenshot`, `evaluate` |
| `--user` | Username for login action |
| `--pass` | Password for login action |
| `--cookies` | Cookie file to use |
| `--state` | Saved browser state file |
| `--save-state` | Save browser state after login |
| `--timeout` | Page load timeout (ms) |
| `--viewport` | Browser viewport size |
| `--headers` | Custom request headers |
| `--pdf` | Save page as PDF instead of screenshot |
| `--block-images` | Block image loading (faster) |
| `--user-agent` | Custom UA string |

## What Playwright can see that curl can't

| Content type | curl/httpx | Playwright |
|-------------|-----------|------------|
| HTML source | ✅ | ✅ |
| Client-side rendered JS | ❌ | ✅ |
| XHR/fetch API responses | ❌ | ✅ (network-log) |
| WebSocket traffic | ❌ | ✅ |
| Browser console errors | ❌ | ✅ |
| Rendered CSS/computed styles | ❌ | ✅ |
| Canvas/WebGL content | ❌ | ✅ |
| Iframe content | ✅ (raw) | ✅ (rendered) |
| Auth-gated content (cookies) | ✅ (with cookie file) | ✅ |
| Auth-gated content (OAuth flow) | ❌ (multi-step) | ✅ |

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| Page times out | JS-heavy SPAs need `--timeout 60000` (60s). Be patient. |
| Login doesn't work | Check if there's a CAPTCHA or MFA. Playwright can handle most auth, but not CAPTCHA. |
| Screenshot is blank | The page may have rendered nothing. Check console logs. |
| "Browser not launching" | Browser dependencies may be missing. Use `npx playwright install-deps`. |
| Anti-bot detection | Some sites detect headless browsers. Use `--user-agent` with a real UA string. |
| Network requests not captured | Wait for page to fully load; some XHR triggers after initial render. |

## Hand-off

- After capturing network logs: `-> /skill/tooling/ffuf` to fuzz discovered API endpoints
- For JS file analysis: `-> /skill/tooling/jsluice` to extract secrets from JS
- For authenticating scans: Use state file from Playwright with `execute_katana` or `execute_nuclei`
- For visual evidence in reports: `-> /skill/reporting/finding_writing` (include screenshots)
- For form brute-force: `-> /skill/tooling/hydra` with `http-post-form` after capturing request format

## Pro tips

- **Screenshots for evidence**: If you find an admin panel or sensitive data, screenshot it immediately. Browser screenshots are the most compelling evidence in penetration test reports.
- **Use network-log for SPA API discovery**: Many SPAs load data from internal APIs. Running Playwright with `--action network-log` reveals endpoints that no crawler would find.
- **Combine with gau for authenticated pages**: Use gau to find historical URLs, then check which ones need auth with Playwright. Auth-gated pages often have different content than public ones.
- **Headless detection bypass**: Sometimes you need extra stealth. Set `--user-agent` to a recent Chrome/Edge UA and use a realistic viewport size (1920x1080).
- **Speed up with --block-images**: If you don't need visual output, blocking images cuts load times by 60-80% on image-heavy pages.

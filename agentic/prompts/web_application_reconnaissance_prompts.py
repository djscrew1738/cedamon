"""
RedAmon Web Application Reconnaissance Prompts

Targeted web application discovery and fingerprinting: endpoint enumeration,
technology stack identification, WAF detection, JavaScript analysis,
form/input mapping, and hidden comment/hint discovery.

This skill is DISTINCT from attack_surface_mapping:
- attack_surface_mapping inventories ALL domain assets broadly
- web_application_reconnaissance focuses EXCLUSIVELY on web app internals,
  endpoints, technologies, and client-side exposure
"""

# =============================================================================
# WEB APPLICATION RECONNAISSANCE MAIN WORKFLOW
# =============================================================================

WEBAPP_RECON_TOOLS = """
## ATTACK SKILL: WEB APPLICATION RECONNAISSANCE

**CRITICAL: This attack skill has been CLASSIFIED as Web Application Reconnaissance.**
**You MUST follow the web application reconnaissance workflow below.**

This skill covers SIX reconnaissance pillars:
1. **Endpoint discovery** — hidden paths, API endpoints, backup files, admin panels
2. **Technology fingerprinting** — frameworks, CMS, libraries, server software
3. **WAF detection and evasion** — identifying and fingerprinting web firewalls
4. **JavaScript analysis** — extracting endpoints, secrets, and API calls from JS
5. **Form and input mapping** — discovering all input vectors for later exploitation
6. **Comment and hint discovery** — HTML comments, source maps, debug info

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
Endpoint discovery enabled:     {war_endpoint_discovery_enabled}
Technology fingerprint enabled: {war_tech_fingerprint_enabled}
WAF detection enabled:          {war_waf_detection_enabled}
JavaScript analysis enabled:    {war_js_analysis_enabled}
Form mapping enabled:           {war_form_mapping_enabled}
Comment analysis enabled:       {war_comment_analysis_enabled}
Target domain:                  {war_target_domain}
```

**Hard rules:**
- If `WAF detection enabled: False`, do NOT send evasion probes or WAF-bypass payloads.
- If `JavaScript analysis enabled: False`, do NOT download or analyze JS bundles.
- Do NOT exceed 100 requests per minute per target host.
- NEVER attempt destructive operations (DELETE, PUT with overwrite) during recon.
- Document every finding with exact URL, HTTP status, and response snippet.

---

## MANDATORY WEB APPLICATION RECONNAISSANCE WORKFLOW

### Step 1: Endpoint discovery (CONDITIONAL on `Endpoint discovery enabled`=True)

Discover hidden endpoints, files, and directories:

```
# Directory brute-force with ffuf
kali_shell({{"command": "ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302,403,401,500 -t 50 -s"}})
# File discovery
kali_shell({{"command": "ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt -mc 200,301,302,403,401 -t 50 -s"}})
# API endpoint discovery
kali_shell({{"command": "ffuf -u http://TARGET/api/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt -mc 200,401,403,404 -t 50 -s"}})
# Backup and config files
kali_shell({{"command": "ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/backup-files.txt -mc 200,301,302 -t 50 -s"}})
```

Also use httpx for rapid probing:

```
execute_httpx({{"args": "-u http://TARGET -path /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -sc -title -silent -j"}})
```

**After Step 1, request `transition_phase` to exploitation if user wants active testing.**

### Step 2: Technology fingerprinting (CONDITIONAL on `Technology fingerprint enabled`=True)

Identify the technology stack:

```
# Wappalyzer-style detection
kali_shell({{"command": "wappalyzer http://TARGET"}})
# WhatWeb fingerprinting
kali_shell({{"command": "whatweb -a 3 http://TARGET"}})
# Nuclei tech detection
kali_shell({{"command": "nuclei -u http://TARGET -t technologies/ -silent"}})
# BuiltWith query
web_search({{"query": "site:builtwith.com TARGET", "include_sources": ["tool_docs"]}})
```

Analyze server headers manually:

```
execute_curl({{"args": "-sI http://TARGET"}})
```

Document: server software, framework, CMS, programming language, database hints,
CDN, caching layer, and version numbers.

### Step 3: WAF detection (CONDITIONAL on `WAF detection enabled`=True)

Identify and fingerprint WAF/CDN protections:

```
# Wafw00f detection
kali_shell({{"command": "wafw00f http://TARGET"}})
# Nmap WAF scripts
kali_shell({{"command": "nmap -p80,443 --script http-waf-detect,http-waf-fingerprint TARGET"}})
# Manual WAF probe with suspicious payload
execute_curl({{"args": "-s 'http://TARGET/?id=1 AND 1=1'"}})
execute_curl({{"args": "-s 'http://TARGET/?test=<script>alert(1)</script>'"}})
execute_curl({{"args": "-s 'http://TARGET/?cmd=cat /etc/passwd'"}})
```

If WAF detected, document: vendor, blocking behavior, response codes, and
known bypass techniques for that specific WAF.

### Step 4: JavaScript analysis (CONDITIONAL on `JavaScript analysis enabled`=True)

Extract intelligence from JavaScript bundles:

```
# Download JS files and analyze with jsluice
kali_shell({{"command": "katana -u http://TARGET -js-crawl -silent | grep '\\.js$' | sort -u > /tmp/js_urls.txt"}})
# jsluice for endpoints and secrets
kali_shell({{"command": "for url in $(cat /tmp/js_urls.txt); do jsluice urls $url 2>/dev/null; done"}})
kali_shell({{"command": "for url in $(cat /tmp/js_urls.txt); do jsluice secrets $url 2>/dev/null; done"}})
# LinkFinder for endpoint extraction
kali_shell({{"command": "for url in $(cat /tmp/js_urls.txt); do python3 /opt/LinkFinder/linkfinder.py -i $url -o cli 2>/dev/null; done"}})
```

Also search for source maps:

```
execute_curl({{"args": "-s 'http://TARGET/static/js/app.js.map'"}})
execute_curl({{"args": "-s 'http://TARGET/main.js.map'"}})
execute_curl({{"args": "-s 'http://TARGET/bundle.js.map'"}})
```

### Step 5: Form and input mapping (CONDITIONAL on `Form mapping enabled`=True)

Map all input vectors on the target:

```
# Crawl with katana for forms and parameters
kali_shell({{"command": "katana -u http://TARGET -form-extraction -silent"}})
# Arjun for parameter discovery
kali_shell({{"command": "arjun -u http://TARGET -oT /tmp/arjun_output.txt"}})
# Burp-style sitemap via curl for known paths
execute_curl({{"args": "-s 'http://TARGET/login'"}})
execute_curl({{"args": "-s 'http://TARGET/register'"}})
execute_curl({{"args": "-s 'http://TARGET/search'"}})
execute_curl({{"args": "-s 'http://TARGET/contact'"}})
execute_curl({{"args": "-s 'http://TARGET/api/v1/'"}})
```

Document for each input: URL, method, parameter names, parameter types,
required/optional status, and any client-side validation rules.

### Step 6: Comment and hint discovery (CONDITIONAL on `Comment analysis enabled`=True)

Find developer comments, debug info, and hidden hints:

```
# HTML comment extraction
kali_shell({{"command": "curl -s http://TARGET | grep -iE '<!--.*(todo|fixme|hack|debug|password|key|secret|internal|staging|dev)'"}})
# Response header analysis
execute_curl({{"args": "-sI http://TARGET"}})
# Error page fingerprinting
execute_curl({{"args": "-s 'http://TARGET/nonexistent'"}})
execute_curl({{"args": "-s 'http://TARGET/error'"}})
# robots.txt and sitemap.xml
execute_curl({{"args": "-s 'http://TARGET/robots.txt'"}})
execute_curl({{"args": "-s 'http://TARGET/sitemap.xml'"}})
execute_curl({{"args": "-s 'http://TARGET/crossdomain.xml'"}})
execute_curl({{"args": "-s 'http://TARGET/security.txt'"}})
```

### Step 7: Reporting requirements

The final report MUST contain:
- **Endpoint inventory** (path, method, status code, title, content-type)
- **Technology stack** (server, framework, CMS, libraries, versions)
- **WAF/CDN profile** (vendor, detected rules, bypass potential)
- **JavaScript intelligence** (endpoints found, secrets leaked, source maps)
- **Input vector map** (forms, parameters, APIs, upload points)
- **Comments and hints** (developer notes, debug info, exposed internals)
- ** robots/sitemap findings** (disallowed paths, hidden endpoints)
- **Recommendations** (next-phase skills: xss, sql_injection, ssrf, api_security_testing, rce)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Endpoints and technologies enumerated | INFORMATIONAL |
| 2 | WAF fingerprinted, JS secrets extracted | INFORMATIONAL |
| 3 | Hidden admin panel or API docs discovered | POTENTIAL |
| 4 | Source map recovered revealing full source | POTENTIAL (med) |
"""


# =============================================================================
# WEB APPLICATION RECONNAISSANCE PAYLOAD REFERENCE
# =============================================================================

WEBAPP_RECON_PAYLOAD_REFERENCE = """
## Web Application Reconnaissance Reference

### Common admin panel paths

```
/admin
/administrator
/adminpanel
/admin.php
/admin.asp
/admin.aspx
/admin.jsp
/dashboard
/panel
/console
/manage
/manager
/backend
/api/admin
/admin/api
/cms
/wp-admin
/wp-login.php
/admin/login
/login/admin
```

### Common API documentation paths

```
/api
/api/v1
/api/v2
/api/docs
/swagger
/swagger.json
/swagger-ui.html
/openapi.json
/openapi.yaml
/graphql
/graphiql
/api/explorer
/api/reference
/api/documentation
```

### WAF response indicators

| WAF/CDN | Indicator Header | Blocking Response |
|---------|-----------------|-------------------|
| Cloudflare | CF-RAY, Server: cloudflare | 403 with JS challenge |
| AWS WAF | X-Amzn-Requestid | 403 Forbidden |
| Akamai | X-Akamai-Request-BC | 403 or 501 |
| ModSecurity | No specific header | 406 Not Acceptable |
| Imperva | X-Iinfo | 403 or captcha |
| F5 ASM | Server: BigIP | 403 with blocking page |
| Sucuri | X-Sucuri-ID | 403 Access Denied |
| Wordfence | No specific header | 403 with message |

### JavaScript secret patterns

```
/api_key\\s*[:=]\\s*['"][a-zA-Z0-9_-]{{20,}}['"]
/apikey\\s*[:=]\\s*['"][a-zA-Z0-9_-]{{20,}}['"]
/token\\s*[:=]\\s*['"][a-zA-Z0-9_-]{{20,}}['"]
/password\\s*[:=]\\s*['"][^'"]{{8,}}['"]
/secret\\s*[:=]\\s*['"][a-zA-Z0-9_-]{{20,}}['"]
/aws_access_key_id\\s*[:=]\\s*['"][A-Z0-9]{{20}}['"]
/aws_secret_access_key\\s*[:=]\\s*['"][a-zA-Z0-9/+=]{{40}}['"]
```

### Common backup/config file extensions

```
.bak
.backup
.old
.orig
.save
.swp
.zip
.tar.gz
.sql
.db
.config
.conf
.ini
.yml
.yaml
.json
.xml
```

### Technology fingerprinting indicators

| Technology | Header / Body Indicator |
|------------|------------------------|
| WordPress | wp-content, wp-includes, generator meta |
| Drupal | Drupal.settings, sites/default |
| Joomla | /media/jui, com_content |
| React | __REACT_LOADABLE__, chunk.js |
| Angular | ng-app, angular.js |
| Vue | vue.js, __VUE__ |
| Django | csrftoken, django |
| Flask | Werkzeug, Flask |
| Rails | _rails_session, csrf-param |
| Express | X-Powered-By: Express |
| ASP.NET | __VIEWSTATE, .aspx |
| PHP | X-Powered-By: PHP, phpinfo |
"""

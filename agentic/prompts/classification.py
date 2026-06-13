"""
RedAmon Attack Skill Classification Prompt

LLM-based classification of user intent to select the appropriate attack skill and phase.
Determines both the attack methodology AND the required phase (informational/exploitation).
Dynamically includes only ENABLED skills in the classification prompt.
"""

from project_settings import get_enabled_builtin_skills, get_enabled_user_skills, get_setting


# =============================================================================
# BUILT-IN SKILL SECTIONS (included when the skill is enabled)
# =============================================================================

_CVE_EXPLOIT_SECTION = """### cve_exploit — CVE (MSF)
- Exploit known CVE vulnerabilities directly against a service using Metasploit Framework (MSF) modules
- Keywords: CVE-XXXX, exploit, RCE, vulnerability, pwn, hack, metasploit
"""

_BRUTE_FORCE_SECTION = """### brute_force_credential_guess
- Password guessing / credential attacks using Hydra against login services (SSH, FTP, MySQL, RDP, SMB, etc.)
- Keywords: brute force, crack password, dictionary attack, wordlist, password spray, guess password, credential attack
"""

_PHISHING_SECTION = """### phishing_social_engineering
- Attack where a target user must execute, open, click, or install something (payload, document, link, one-liner)
- Includes: msfvenom payloads, document-based payloads, web delivery, email delivery, handler setup
- Key distinction: target user runs artifact on THEIR machine (vs cve_exploit which hits a service directly)
- Keywords: payload, reverse shell, msfvenom, payload delivery, phishing, document payload, handler
"""

_DOS_SECTION = """### denial_of_service
- Attacks that DISRUPT service availability rather than gaining access or stealing data
- Includes: DoS modules, flooding, slowloris, resource exhaustion, crash exploits
- Key distinction: goal is DISRUPTION/CRASH/UNAVAILABILITY — no shell, no credentials, no data theft
- Keywords: dos, denial of service, crash, disrupt, availability, slowloris, flood, exhaust, stress test, take down, knock offline, overwhelm
"""

_SQLI_SECTION = """### sql_injection — SQL Injection
- SQL injection testing against web applications using SQLMap and manual techniques
- Includes: error-based, union-based, blind boolean, blind time-based, out-of-band (OOB/DNS exfiltration)
- Key distinction: injecting SQL into application parameters to extract data or gain access
- Keywords: SQL injection, SQLi, sqlmap, database dump, union select, blind injection, WAF bypass, authentication bypass
"""

_XSS_SECTION = """### xss — Cross-Site Scripting (XSS)
- XSS testing against web applications using dalfox, kxss, Playwright DOM analysis, and manual context-aware payloads
- Includes: reflected XSS, stored XSS, DOM-based XSS, blind XSS via OOB callbacks, CSP bypass
- Key distinction: injecting JavaScript that executes in a victim's browser context (vs sql_injection which targets the DB, vs ssrf which targets the backend)
- Keywords: XSS, cross-site scripting, reflected XSS, stored XSS, DOM XSS, blind XSS, dalfox, payload encoding, CSP bypass, innerHTML, event handler, script injection
"""

_SSRF_SECTION = """### ssrf — Server-Side Request Forgery (SSRF)
- SSRF testing against web applications: forcing the server to make requests to internal services, cloud metadata endpoints, or arbitrary destinations the attacker cannot reach directly
- Includes: classic / blind / semi-blind SSRF, cloud metadata pivots (AWS IMDS, GCP/Azure metadata), protocol smuggling (gopher, file, dict), DNS rebinding, URL parser confusion, redirect chains, internal port scanning via SSRF, RCE chains via Redis/FastCGI/Docker
- Key distinction: the server fetches an attacker-controlled URL (vs sql_injection which manipulates DB queries, vs xss which executes JS in a victim browser, vs phishing which builds artifacts for a target user)
- Keywords: SSRF, server-side request forgery, internal request, cloud metadata, IMDS, IMDSv2, gopher, redirect bypass, DNS rebinding, internal SSRF, blind SSRF, webhook abuse, URL fetcher, link preview, parser differential, CRLF injection, OAST callback
"""

_RCE_SECTION = """### rce — Remote Code Execution (RCE) / Command Injection
- RCE testing against web applications and services: forcing the target to execute attacker-controlled code via OS command injection, server-side template injection (SSTI), insecure deserialization, dynamic eval / expression languages, media + document pipelines, or SSRF-to-RCE chains
- Includes: command injection (commix), SSTI across Jinja2/Twig/Freemarker/Velocity/EJS/Thymeleaf (sstimap), Java deserialization gadget chains (ysoserial: URLDNS, CommonsCollections, Spring), PHP unserialize, Python pickle, Ruby Marshal, .NET ViewState, OGNL/SpEL/MVEL injection, ImageMagick/Ghostscript/ExifTool/LaTeX pipeline RCE, Log4Shell-style JNDI lookups, Spring4Shell, Struts S2-045, container/k8s escape probes, OOB DNS oracles via interactsh
- Key distinction: code or shell commands execute on the SERVER (vs xss which runs JS in a victim browser, vs sql_injection which only injects SQL into a DB, vs ssrf which forces outbound HTTP fetches without code execution, vs cve_exploit which uses Metasploit modules against pre-known CVEs in network services, vs path_traversal which only reads files unless escalated via a wrapper-and-log-poisoning chain)
- Keywords: RCE, remote code execution, command injection, code injection, shell injection, SSTI, server-side template injection, template injection, deserialization, gadget chain, ysoserial, commix, sstimap, eval, exec, system command, OGNL, SpEL, MVEL, log4shell, log4j, spring4shell, struts, ImageMagick, ImageTragick, Ghostscript, ExifTool, JNDI, picture upload RCE, Jinja2 SSTI, Freemarker SSTI, Twig SSTI, pickle RCE, container escape, docker.sock
"""

_PATH_TRAVERSAL_SECTION = """### path_traversal — Path Traversal / LFI / RFI
- File-disclosure testing against web applications: coercing the target to read or include files outside the intended root via `../` traversal, encoded variants, normalisation gaps, PHP wrappers (`php://filter`, `data://`, `expect://`, `zip://`), log poisoning, remote inclusion (RFI) via `http://`/`ftp://` schemes, and archive-extraction (Zip Slip)
- Includes: classic path traversal, Local File Inclusion (LFI), Remote File Inclusion (RFI), PHP wrapper-driven source disclosure, log poisoning to RCE, /proc and cloud-credential file reads, parser/normalisation mismatches across nginx + backend (`..;/`, `%252f` double-decode), Windows UNC and absolute-path acceptance, archive entries with `../` or symlinks that escape the extraction directory
- Key distinction: the goal is to READ (or write via Zip Slip) a file outside the intended root (vs sql_injection which targets the database, vs xss which executes JS in a browser, vs ssrf which forces outbound HTTP fetches without filesystem access, vs rce which runs code on the server unless this skill chains LFI + log poisoning to escalate, vs cve_exploit which uses Metasploit modules against pre-known CVEs)
- Keywords: path traversal, directory traversal, LFI, local file inclusion, RFI, remote file inclusion, file inclusion, file read, arbitrary file read, ../, %2e%2e%2f, php://filter, data://, expect://, zip://, file://, log poisoning, /etc/passwd, /etc/hosts, web.config, win.ini, wp-config, .env disclosure, SecLists fuzz file, nginx alias bypass, ..;/, double-decode, Zip Slip, archive extraction, tarslip, symlink archive
"""

_LLM_SECURITY_SECTION = """### llm_security — GenAI / LLM Security
- Testing LLM-powered applications for prompt injection (direct and indirect), jailbreaking, model extraction, training-data leakage, LLM API abuse, RAG pipeline poisoning, content-filter bypass, and excessive-agency exploits
- Includes: direct prompt injection via user-facing LLM inputs, indirect (second-order) injection via retrieved RAG context, jailbreak encoding (base64, leetspeak, role-play, token-smuggling), model inversion / extraction via API probing, training-data extraction via membership inference, LLM API abuse (function-call / tool-use subversion, excessive agency), embedding-vector store poisoning, output-guard / safety-filter bypass, prompt-leaking via error messages
- Key distinction: the target is an LLM application layer — prompt inputs, RAG documents, embedding stores, or model APIs (vs rce which targets server-side code execution via injection into non-LLM interpreters, vs ssrf which forces the server to make outbound HTTP requests, vs sql_injection which targets database query parsers)
- Keywords: LLM, prompt injection, jailbreak, RAG poisoning, model extraction, training data leakage, membership inference, guardrail bypass, content filter bypass, excessive agency, function calling abuse, tool use hijack, embedding poisoning, indirect prompt injection, second-order injection, GPT, Claude, Llama, chatbot, AI agent, generative AI, large language model
"""

_CICD_PIPELINE_SECTION = """### cicd_pipeline — CI/CD Pipeline Attacks
- Exploiting weaknesses in CI/CD pipelines (GitHub Actions, GitLab CI, Jenkins, CircleCI) to compromise build artifacts, exfiltrate secrets, escalate from pull-request to production, pivot across linked pipelines, or poison the software supply chain
- Includes: GITHUB_TOKEN / CI secret exposure via malicious PR, self-hosted runner compromise (fork PR trigger, repo-jacking), artifact poisoning (malicious build outputs, PyPI/npm/Go module confusion), dependency confusion / typo-squatting in CI-installed packages, `pull_request_target` workflow exploitation, `workflow_run` chained-trigger abuse, cache poisoning (action cache, pip/npm cache), matrix-build injection, third-party action pinning bypass, GitLab CI `trigger`-pipeline cross-project pivot, Jenkins Shared Library code injection, CircleCI orb poisoning, CodeBuild / CodePipeline IAM role abuse
- Key distinction: the target is the CI/CD INFRASTRUCTURE or PIPELINE LOGIC itself (vs supply-chain attacks that target end-user dependencies which belong to unclassified, vs cve_exploit which targets deployed services, vs rce which targets server-side code execution)
- Keywords: CI/CD, pipeline, GitHub Actions, GitLab CI, Jenkins, CircleCI, build pipeline, pull request attack, PR exploit, GITHUB_TOKEN, self-hosted runner, artifact poisoning, dependency confusion, typo-squatting, pull_request_target, workflow_run, cache poisoning, third-party action, orb poisoning, supply chain, build compromise, continuous integration, continuous delivery
"""

_BROWSER_EXPLOITATION_SECTION = """### browser_exploitation — Browser & Electron Exploitation
- Exploiting browser-based and Electron-based desktop applications via IPC abuse, extension attacks, DevTools protocol hijacking, DOM clobbering, service worker interception, and web-to-native bridge exploitation
- Includes: Electron IPC channel sniffing / `invoke` spoofing / `contextBridge` leakage / `preload` script bypass / `nodeIntegration` abuse / `shell.openExternal` argument injection, Chrome extension message-passing hijack (`runtime.sendMessage`, `tabs.sendMessage`), DevTools protocol hijack via `chrome-devtools://` or exposed 9222 port, DOM clobbering via `id`/`name` collisions overwriting built-in globals, service worker registration hijack + fetch-event interception, postMessage origin-confusion / wildcard targetOrigin, SameSite cookie nuance (Lax/None bypass via top-level navigation), browser-in-the-browser (BitB) phishing, Chrome headless / Puppeteer RCE via `--remote-debugging-port`
- Key distinction: the attack surface is CLIENT-SIDE — a desktop app built on Electron, a browser extension, or the browser runtime itself (vs xss which injects JS into a web page, vs rce which targets server-side interpreters, vs phishing which builds payloads for the user to execute)
- Keywords: Electron, IPC, contextBridge, preload, nodeIntegration, shell.openExternal, Chrome extension, DevTools, DOM clobbering, service worker, postMessage, SameSite bypass, BitB, browser, headless Chrome, Puppeteer, desktop app, CVE, remote debugging, chromium
"""

_CONTAINER_K8S_SECTION = """### container_k8s — Container & Kubernetes Security
- Assessing and exploiting containerised and Kubernetes environments: registry analysis, image-layer inspection, K8s RBAC enumeration, pod breakout, etcd exposure, admission controller abuse, and cluster-wide privilege escalation
- Includes: container registry crawling (Docker Hub, ECR, GCR, ACR, private registries) for exposed secrets / hardcoded creds in image layers via `dive`-style layer inspection / `history` analysis, Kubernetes RBAC enumeration via `kubectl auth can-i` / token-review, pod breakout via privileged containers / `CAP_SYS_ADMIN` / hostPID / hostNetwork / `hostPath` mount escape, `kubelet` anonymous-auth abuse, `etcd` direct read when exposed, admission controller webhook bypass / mutation-webhook injection, `kubeconfig` credential extraction from CI env / `~/.kube/config`, service-account token abuse, `ClusterRoleBinding` / `RoleBinding` escalation, `PodSecurityPolicy` / `PodSecurity` bypass, `secrets` enumeration via API server, namespace-hopping via `kubectl exec` pivot, `kubefwd` / `telepresence` sidecar injection
- Key distinction: the target is CONTAINER / ORCHESTRATION INFRASTRUCTURE — registry, image, kubelet, API server, etcd (vs docker_escape_post_exploitation which is a post-exploitation skill for escaping a container the agent already has a shell in, vs cve_exploit which targets specific CVEs in deployed services)
- Keywords: container, Docker, Kubernetes, K8s, pod, kubelet, etcd, RBAC, ClusterRole, service account, admission controller, image layer, container registry, ECR, GCR, ACR, Docker Hub, pod escape, container breakout, kubeconfig, namespace, kubectl, privileged container, CAP_SYS_ADMIN, hostPath, sidecar injection
"""

_HYBRID_IDENTITY_SECTION = """### hybrid_identity — Hybrid Identity & Federation Attacks
- Attacking hybrid identity systems spanning on-premises Active Directory and cloud identity providers (Azure AD / Entra ID, ADFS, Okta): federation trust abuse, token manipulation, Kerberos delegation weaponisation, and cross-forest / cross-tenant pivots
- Includes: AD FS (Active Directory Federation Services) endpoint enumeration / `adfs/ls/wia` endpoint probing / token-signing certificate theft via DA-in-ADFS, Azure AD Connect (AADC) account extraction / password hash sync interception / pass-through authentication (PTA) agent credential theft, Kerberos unconstrained delegation abuse via TGT capture on member servers, Kerberos constrained delegation `S4U2Self` / `S4U2Proxy` abuse (`s4u2self` / `s4u2proxy`), RBCD (Resource-Based Constrained Delegation) configuration of `msDS-AllowedToActOnBehalfOfOtherIdentity`, Kerberos Bronze Bit attack (CVE-2020-17049), cross-forest SIDHistory / trust ticket abuse (`extra_sids` in TGT), Azure AD / Entra ID device-code phishing / consent-grant abuse / refresh token theft, federated domain trust poisoning (SAML assertion signing with stolen cert), cloud-to-on-premises token broker abuse (DG/MDG, PRT, PRT-to-TGT)
- Key distinction: the target is IDENTITY & AUTHENTICATION INFRASTRUCTURE that bridges on-prem AD with cloud IdP (vs ad_kill_chain and bloodhound_path_to_da which focus on on-prem AD attacks without federation, vs cve_exploit which targets specific CVEs, vs unclassified credential-theft)
- Keywords: hybrid identity, federation, AD FS, ADFS, Azure AD Connect, AADC, pass-through authentication, PTA, Kerberos delegation, constrained delegation, unconstrained delegation, RBCD, S4U2Self, S4U2Proxy, Bronze Bit, CVE-2020-17049, SAML, federated trust, token signing, device code phishing, consent grant, Entra ID, Azure AD, Okta, identity federation, cross-forest, SIDHistory, token theft, PRT, primary refresh token
"""

_AD_KILL_CHAIN_SECTION = """### ad_kill_chain — Active Directory Kill Chain
- Full on-premises Active Directory compromise: reconnaissance, credential attacks, BloodHound path analysis, ACL abuse, Kerberos attacks, lateral movement, and Domain Admin attainment
- Includes: user enumeration, share enumeration, LDAP recon, BloodHound ingest, AS-REP roasting, Kerberoasting, password spraying, NTLM relay, delegation abuse (unconstrained / constrained / RBCD), AD CS exploitation (ESC1-ESC13), DCSync, pass-the-hash, overpass-the-hash, Golden Ticket, Silver Ticket, DCShadow
- Key distinction: pure ON-PREM AD without federation or cloud bridging (vs hybrid_identity which covers federation and cloud IdP, vs cve_exploit which targets specific CVEs in services)
- Keywords: Active Directory, AD, BloodHound, Kerberoast, AS-REP roast, DCSync, pass the hash, PtH, overpass the hash, Golden Ticket, Silver Ticket, DCShadow, ACL abuse, delegation, RBCD, AD CS, ESC1, ESC8, lateral movement, domain admin, DA, netexec, impacket, certipy, kerbrute, bloodhound-python, enum4linux
"""

_CLOUD_INFRA_SECTION = """### cloud_infra_exploitation — Cloud Infrastructure Exploitation
- AWS, GCP, and Azure cloud-native misconfiguration exploitation: IAM policy abuse, metadata service attacks, storage enumeration, serverless abuse, cross-account pivot, and privilege escalation
- Includes: EC2 IMDSv1/v2 abuse, AWS S3 enumeration / public bucket discovery, Lambda function env exfiltration, IAM role assumption, GCP Compute metadata / service account token theft, Azure VM metadata / Managed Identity token abuse, cross-account / cross-project / cross-tenant pivots, Secrets Manager / Key Vault harvesting, cloud credential theft from workload identity
- Key distinction: targets the CLOUD CONTROL PLANE and MANAGED SERVICES directly (vs container_k8s which targets orchestration, vs ssrf which is a single HTTP fetcher abuse vector, vs hybrid_identity which covers federation)
- Keywords: AWS, GCP, Azure, cloud, IAM, S3, Lambda, metadata, IMDS, IMDSv2, instance metadata, service account, managed identity, cross account, privilege escalation, cloud storage, bucket, secrets manager, key vault, assume role, STS, cloud function, serverless, boto3, azure-identity, google-auth
"""

_API_SECURITY_SECTION = """### api_security_testing — API Security Testing
- REST, GraphQL, and gRPC API security testing: authentication/authorization flaws, IDOR, BOLA, BFLA, JWT/OAuth2 abuse, GraphQL introspection/batching, mass assignment, and rate-limit bypass
- Includes: OpenAPI/Swagger discovery, HTTP method switching, JWT algorithm confusion / weak secret / kid injection, OAuth2 redirect_uri abuse / implicit flow / missing PKCE, GraphQL introspection / query depth abuse / batching / field suggestions, gRPC proto reflection, API versioning issues, mass assignment, API key leakage, documentation leakage
- Key distinction: API-specific DESIGN and LOGIC flaws (vs sql_injection, xss, ssrf, rce which are injection primitives that may appear in API parameters)
- Keywords: API, REST, GraphQL, gRPC, IDOR, BOLA, BFLA, JWT, OAuth2, mass assignment, rate limit, API key, introspection, batching, swagger, openapi, endpoint, authorization, broken object level authorization, broken function level authorization, graphqlmap, graphql-cop, jwt_tool
"""

_SUPPLY_CHAIN_SECTION = """### supply_chain_poisoning — Supply Chain Poisoning
- Software supply chain attacks: dependency confusion, typo-squatting, malicious package injection, manifest poisoning, and signature-verification bypass
- Includes: publishing higher-version malicious packages to public registries matching internal names, registering typo-squat names of popular libraries, backdooring legitimate packages via compromised maintainer or malicious PR, altering manifest/lockfiles to inject malicious dependencies, bypassing package signature verification / SBOM validation / attestation checks
- Key distinction: targets ARTIFACTS and DEPENDENCIES produced/consumed (vs cicd_pipeline which targets the CI/CD infrastructure itself, vs unclassified file-upload attacks)
- Keywords: supply chain, dependency confusion, typo-squatting, typo squat, malicious package, npm, pip, PyPI, maven, nuget, cargo, composer, manifest poisoning, lockfile, SBOM, signature bypass, package registry, semver, package.json, requirements.txt, go.mod, Cargo.toml
"""

_DOMAIN_TAKEOVER_SECTION = """### domain_takeover — Domain Takeover
- Subdomain takeover, domain hijacking, and DNS security: dangling CNAMEs, expired NS delegations, unclaimed cloud resources, and vulnerable DNS configurations
- Includes: dangling CNAME to deleted/unclaimed cloud resources (S3, CloudFront, GitHub Pages, Heroku, Azure, etc.), expired nameserver delegation hijack, domain expiry/re-registration, misconfigured wildcard DNS, MX/TXT/SPF/DKIM gaps enabling email spoofing infrastructure
- Key distinction: DNS and domain-level control acquisition (vs cloud_infra_exploitation which targets cloud APIs, vs phishing_social_engineering which uses domains for delivery rather than acquiring control)
- Keywords: subdomain takeover, domain takeover, DNS hijack, CNAME, dangling CNAME, nameserver, NS record, domain expiry, wildcard DNS, SPF, DMARC, DKIM, email spoofing, S3 bucket takeover, CloudFront, GitHub Pages, Heroku, Azure App Service, subzy, dnsx
"""

_ATTACK_SURFACE_MAPPING_SECTION = """### attack_surface_mapping — Attack Surface Mapping
- Comprehensive domain-wide reconnaissance and attack surface enumeration combining passive OSINT, active probing, and graph-based correlation
- Includes: subdomain discovery (passive + active), port scanning, HTTP probing, web crawling, JavaScript analysis, technology fingerprinting, certificate transparency analysis, ASN/BGP mapping, API endpoint discovery, parameter enumeration
- Key distinction: aims for a COMPLETE inventory of all domain assets regardless of vulnerability (vs domain_takeover which focuses on DNS control, vs infrastructure_exposure_analysis which focuses only on exposed/misconfigured assets)
- Keywords: attack surface, reconnaissance, subdomain enumeration, osint, port scan, service discovery, technology fingerprint, web crawl, endpoint discovery, parameter enumeration, certificate transparency, ASN, BGP, asset inventory, attack surface mapping
"""

_SUBDOMAIN_RECONNAISSANCE_SECTION = """### subdomain_reconnaissance — Subdomain Reconnaissance
- Focused subdomain enumeration and validation: passive discovery, active brute-force, permutation generation, DNS resolution, and takeover fingerprinting
- Includes: certificate transparency log querying, passive DNS aggregation, DNS dictionary brute-force, subdomain permutation with altdns/dnsgen, massDNS high-speed resolution, CNAME chain analysis, dangling CNAME takeover detection, zone transfer attempts, DNSSEC validation
- Key distinction: focuses EXCLUSIVELY on subdomain discovery and DNS analysis (vs attack_surface_mapping which inventories all assets broadly, vs domain_takeover which focuses on acquiring control of DNS records)
- Keywords: subdomain, subdomain enumeration, subfinder, amass, dnsx, massdns, altdns, dnsgen, certificate transparency, crt.sh, passive dns, zone transfer, AXFR, CNAME, dangling CNAME, subdomain takeover, DNS brute-force, subdomain permutation, DNS resolution
"""

_EMAIL_SECURITY_SECTION = """### email_security_assessment — Email Security Assessment
- Domain-level email infrastructure security testing: SPF, DMARC, DKIM, MX record analysis, open relay detection, email header injection, mailbox enumeration, and BEC infrastructure testing
- Includes: DNS record analysis (SPF/DMARC/DKIM/MX/MTA-STS/TLS-RPT/BIMI), email spoofing proof-of-concept, open relay / SMTP misconfiguration testing, SMTP VRFY/RCPT TO mailbox enumeration, email header injection via web forms, lookalike domain detection for BEC
- Key distinction: tests the DOMAIN'S email security CONFIGURATION (vs phishing_social_engineering which builds payloads for users to execute, vs domain_takeover which focuses on DNS control acquisition)
- Keywords: email security, SPF, DMARC, DKIM, MX record, email spoofing, open relay, SMTP, VRFY, RCPT TO, mailbox enumeration, header injection, BEC, business email compromise, lookalike domain, MTA-STS, BIMI, mail infrastructure
"""

_WEB_CACHE_POISONING_SECTION = """### web_cache_poisoning — Web Cache Poisoning
- Web cache deception and poisoning attacks: cache key manipulation, header-based cache poisoning, parameter cloaking, CDN-specific bypasses, and cache-busting attacks
- Includes: cache fingerprinting (CDN identification, cache headers, TTL, key components), unkeyed input discovery (headers/parameters not in cache key), header-based poisoning (X-Forwarded-Host, X-Forwarded-Proto, Origin, Referer), parameter cloaking (first-last split, encoding differential), cache deception (path confusion, extension swap, method override), CDN-specific tests (Cloudflare, Fastly, Akamai, CloudFront, Varnish)
- Key distinction: targets the HTTP CACHE LAYER specifically (vs xss which targets browser JS execution, vs ssrf which forces server-side fetches, vs rce which executes code on the server)
- Keywords: cache poisoning, web cache, CDN, cache deception, cache key, unkeyed input, X-Forwarded-Host, parameter cloaking, Cloudflare, Fastly, Akamai, Varnish, cache busting, header injection, cache miss, cache hit
"""

_WEB_APPLICATION_RECONNAISSANCE_SECTION = """### web_application_reconnaissance — Web Application Reconnaissance
- Targeted web application discovery and fingerprinting: endpoint enumeration, technology stack identification, WAF detection, JavaScript analysis, form/input mapping, and hidden comment/hint discovery
- Includes: directory and file brute-force, API endpoint discovery, technology fingerprinting (Wappalyzer, WhatWeb, Nuclei), WAF fingerprinting (wafw00f, nmap scripts), JavaScript endpoint extraction (jsluice, LinkFinder), source map recovery, form and input vector mapping, HTML comment analysis, robots.txt/sitemap.xml parsing, error page fingerprinting
- Key distinction: focuses EXCLUSIVELY on web application internals and client-side exposure (vs attack_surface_mapping which inventories all domain assets broadly, vs api_security_testing which tests API security flaws)
- Keywords: web app recon, endpoint discovery, technology fingerprint, WAF detection, JavaScript analysis, JS secrets, source map, form mapping, input vectors, HTML comments, directory brute-force, ffuf, katana, jsluice, wafw00f, whatweb, admin panel, api docs, swagger, openapi
"""

_TRANSPORT_SECURITY_SECTION = """### transport_security_assessment — Transport Security Assessment
- Domain-wide TLS/SSL configuration, certificate chain, cipher suite, and transport-layer security testing
- Includes: TLS version analysis (SSLv2/v3, TLS 1.0/1.1/1.2/1.3), cipher suite enumeration (weak/deprecated ciphers, forward secrecy), certificate chain validation (trust, expiry, revocation, SAN coverage), HSTS and security headers (preload, includeSubDomains, Expect-CT), downgrade vulnerability testing (POODLE, BEAST, CRIME, Logjam, Sweet32, ROBOT, Heartbleed), subdomain TLS consistency scanning
- Key distinction: deep TRANSPORT-LAYER configuration assessment (vs attack_surface_mapping which notes TLS as one data point, vs cve_exploit which targets specific CVEs in services)
- Keywords: TLS, SSL, transport security, certificate, cipher suite, HSTS, downgrade, POODLE, BEAST, CRIME, Logjam, Heartbleed, ROBOT, testssl, OCSP, certificate transparency, forward secrecy, TLS 1.3, SSLv3
"""

_INFRASTRUCTURE_EXPOSURE_SECTION = """### infrastructure_exposure_analysis — Infrastructure Exposure Analysis
- Discovery of exposed, misconfigured, or unintentionally public infrastructure: open databases, exposed cloud storage, unauthenticated APIs, shadow IT, and internet-facing management interfaces
- Includes: public S3/GCS/Azure Blob buckets, unauthenticated ElasticSearch/MongoDB/Redis, exposed admin panels (phpMyAdmin, Jenkins, Grafana, Kibana), Swagger/OpenAPI docs without auth, GraphQL introspection on production, exposed .git directories and source code, backup archives, .env files, shadow IT subdomains (dev/staging/test), secret leakage in JS bundles
- Key distinction: focuses on EXPOSED/VULNERABLE assets visible from the internet (vs attack_surface_mapping which inventories ALL assets, vs cloud_infra_exploitation which requires cloud credentials/control plane access)
- Keywords: exposed infrastructure, open database, public bucket, shadow IT, exposed admin panel, unauthenticated API, .git exposure, backup leak, secret leak, exposed storage, ElasticSearch, MongoDB, Redis, Jenkins, Grafana, phpMyAdmin, source code leak
"""

_UNCLASSIFIED_SECTION = """### <descriptive_term>-unclassified
- ANY exploitation request that does NOT clearly fit the enabled attack skills above
- The agent has no specialized workflow for these — it will use available tools generically
- **Key distinction from phishing:** the attacker directly interacts with a SERVICE/APPLICATION, NOT generating a payload for a target user to execute
  - "Try to abuse the bulk-export endpoint" → unclassified (attacker sends crafted input to a web service)
  - "Generate a reverse shell payload" → phishing (attacker creates a file for a target user to execute)
- **Key distinction from sql_injection:** if the request is specifically about SQL injection, use the `sql_injection` skill instead
- **Key distinction from xss:** if the request is specifically about XSS, cross-site scripting, or JavaScript injection in a browser, use the `xss` skill instead
- **Key distinction from ssrf:** if the request is specifically about SSRF, server-side request forgery, cloud metadata access, or forcing the server to make outbound requests, use the `ssrf` skill instead
- **Key distinction from rce:** if the request is specifically about command injection, SSTI, deserialization gadget chains, eval / OGNL / SpEL injection, media-pipeline RCE, or any other path leading to remote CODE/SHELL execution on the server, use the `rce` skill instead
- **Key distinction from path_traversal:** if the request is specifically about path traversal, directory traversal, LFI, RFI, file inclusion, PHP wrappers (`php://filter`, `data://`, `expect://`), log poisoning, or Zip Slip / archive-extraction file writes, use the `path_traversal` skill instead
- You MUST create a short, descriptive snake_case term followed by "-unclassified"
- Format: `<term>-unclassified` where term is 1-4 lowercase words joined by underscores
- Example values: "file_upload-unclassified", "xxe-unclassified", "race_condition-unclassified"
- Keywords: file upload, XXE, privilege escalation, race conditions
- Example requests:
  - "Try to upload a web shell" -> "file_upload-unclassified"
  - "Test for XXE on the SOAP endpoint" -> "xxe-unclassified"
"""

# Map of built-in skill ID -> (section text, classification priority letter)
_BUILTIN_SKILL_MAP = {
    'phishing_social_engineering': (_PHISHING_SECTION, 'a', 'phishing_social_engineering'),
    'brute_force_credential_guess': (_BRUTE_FORCE_SECTION, 'b', 'brute_force_credential_guess'),
    'cve_exploit': (_CVE_EXPLOIT_SECTION, 'c', 'cve_exploit'),
    'denial_of_service': (_DOS_SECTION, 'd', 'denial_of_service'),
    'sql_injection': (_SQLI_SECTION, 'e', 'sql_injection'),
    'xss': (_XSS_SECTION, 'f', 'xss'),
    'ssrf': (_SSRF_SECTION, 'g', 'ssrf'),
    'rce': (_RCE_SECTION, 'h', 'rce'),
    'path_traversal': (_PATH_TRAVERSAL_SECTION, 'i', 'path_traversal'),
    'llm_security': (_LLM_SECURITY_SECTION, 'j', 'llm_security'),
    'cicd_pipeline': (_CICD_PIPELINE_SECTION, 'k', 'cicd_pipeline'),
    'browser_exploitation': (_BROWSER_EXPLOITATION_SECTION, 'l', 'browser_exploitation'),
    'container_k8s': (_CONTAINER_K8S_SECTION, 'm', 'container_k8s'),
    'hybrid_identity': (_HYBRID_IDENTITY_SECTION, 'n', 'hybrid_identity'),
    'ad_kill_chain': (_AD_KILL_CHAIN_SECTION, 'o', 'ad_kill_chain'),
    'cloud_infra_exploitation': (_CLOUD_INFRA_SECTION, 'p', 'cloud_infra_exploitation'),
    'api_security_testing': (_API_SECURITY_SECTION, 'q', 'api_security_testing'),
    'supply_chain_poisoning': (_SUPPLY_CHAIN_SECTION, 'r', 'supply_chain_poisoning'),
    'domain_takeover': (_DOMAIN_TAKEOVER_SECTION, 's', 'domain_takeover'),
    'attack_surface_mapping': (_ATTACK_SURFACE_MAPPING_SECTION, 't', 'attack_surface_mapping'),
    'subdomain_reconnaissance': (_SUBDOMAIN_RECONNAISSANCE_SECTION, 'y', 'subdomain_reconnaissance'),
    'email_security_assessment': (_EMAIL_SECURITY_SECTION, 'u', 'email_security_assessment'),
    'web_cache_poisoning': (_WEB_CACHE_POISONING_SECTION, 'v', 'web_cache_poisoning'),
    'web_application_reconnaissance': (_WEB_APPLICATION_RECONNAISSANCE_SECTION, 'z', 'web_application_reconnaissance'),
    'transport_security_assessment': (_TRANSPORT_SECURITY_SECTION, 'w', 'transport_security_assessment'),
    'infrastructure_exposure_analysis': (_INFRASTRUCTURE_EXPOSURE_SECTION, 'x', 'infrastructure_exposure_analysis'),
}

# Classification instructions for built-in skills (no priority — best match wins)
_CLASSIFICATION_INSTRUCTIONS = {
    'phishing_social_engineering': """   - **phishing_social_engineering**:
      - Is the request asking to GENERATE, CREATE, or SET UP a payload, malicious file, document, backdoor, reverse shell, one-liner, or delivery server?
      - Will the output be something a target user must execute, open, click, or install on their machine?
      - Does it mention msfvenom, handler, multi/handler, web delivery, HTA server, encoding for AV evasion?
      - Does it mention sending something via email to a target person?""",
    'brute_force_credential_guess': """   - **brute_force_credential_guess**:
      - Does the request mention password guessing, brute force, credential attacks, wordlists, or dictionary attacks?
      - Does it target a login service (SSH, FTP, MySQL, etc.) with credential-based attack?""",
    'cve_exploit': """   - **cve_exploit**:
      - Does the request mention a specific CVE ID or Metasploit exploit module to use DIRECTLY against a service?
      - Does it describe exploiting a service vulnerability where NO target user interaction is needed?""",
    'denial_of_service': """   - **denial_of_service**:
      - Is the goal to DISRUPT, CRASH, or make a service UNAVAILABLE (not to gain access)?
      - Does it mention DoS, denial of service, flooding, slowloris, stress test, take down, exhaust resources?
      - Is the user NOT trying to get a shell, steal data, or obtain credentials?""",
    'sql_injection': """   - **sql_injection**:
      - Does the request mention SQL injection, SQLi, database dumping, or union/blind injection?
      - Does it target a web application parameter with SQL-specific attack intent?
      - Does it mention sqlmap, WAF bypass for SQL, authentication bypass via SQL, or OOB/DNS exfiltration?""",
    'xss': """   - **xss**:
      - Does the request mention XSS, cross-site scripting, JavaScript injection, or DOM sinks?
      - Does it target a web application input/parameter with the goal of executing JS in a victim browser?
      - Does it mention reflected/stored/DOM XSS, payload encoding, CSP bypass, blind XSS callbacks, or dalfox?""",
    'ssrf': """   - **ssrf**:
      - Does the request mention SSRF, server-side request forgery, internal request, or webhook abuse?
      - Does it target a URL/host/redirect parameter with the goal of forcing the server to fetch attacker-controlled or internal destinations?
      - Does it mention cloud metadata (IMDS, 169.254.169.254, metadata.google.internal), gopher://, DNS rebinding, or internal port scanning via URL fetcher?
      - Does it describe parser confusion, redirect chains, or CRLF injection in URL parameters?""",
    'rce': """   - **rce**:
      - Does the request mention RCE, remote code execution, command injection, code injection, or shell execution on the server?
      - Does it mention server-side template injection (SSTI), Jinja2 / Twig / Freemarker / Velocity / EJS / Thymeleaf payloads?
      - Does it mention insecure deserialization, gadget chains, ysoserial, pickle, PHP unserialize, ViewState, or Marshal.load?
      - Does it mention eval / exec / OGNL / SpEL / MVEL injection, or expression-language abuse?
      - Does it mention Log4Shell / JNDI, Spring4Shell, Struts S2-045, ImageMagick / Ghostscript / ExifTool / LaTeX pipeline RCE?
      - Does it describe a path that ends in a SHELL or CODE running on the server (not just data extraction or browser-side JS)?""",
    'path_traversal': """   - **path_traversal**:
      - Does the request mention path traversal, directory traversal, LFI, RFI, file inclusion, or arbitrary file read?
      - Does it mention `../`, `%2e%2e%2f`, `..;/`, double-decode, or nginx alias bypass?
      - Does it mention PHP wrappers (`php://filter`, `data://`, `expect://`, `zip://`) or log poisoning to escalate LFI?
      - Does it mention reading sensitive files like `/etc/passwd`, `/etc/hosts`, `/proc/self/environ`, `wp-config.php`, `.env`, `web.config`, or cloud credential files?
      - Does it mention archive-extraction (Zip Slip / TarSlip), symlink-in-archive escapes, or writing files outside an extraction directory?
      - Key boundary: STOP before this skill if the goal is direct command execution -- that belongs to `rce` -- unless the request explicitly chains LFI + log poisoning to land RCE (then it stays here).""",
    'llm_security': """   - **llm_security**:
      - Does the request mention an LLM, chatbot, AI agent, GPT, Claude, Llama, or generative AI application?
      - Does it mention prompt injection, jailbreaking, prompt leaking, or convincing the AI to bypass its guardrails?
      - Does it mention RAG, retrieval-augmented generation, vector database, embedding store, or knowledge base poisoning?
      - Does it mention model extraction, model theft, training data leakage, membership inference, or model inversion?
      - Does it mention LLM API function calling abuse, tool-use hijacking, excessive agency, or plugin exploitation?
      - Does it mention content filter bypass, output guardrail evasion, or safety classifier circumvention?
      - Key boundary: if the request is about classic SQL/command injection into a non-LLM app, use `sql_injection` or `rce` instead.""",
    'cicd_pipeline': """   - **cicd_pipeline**:
      - Does the request mention CI/CD, GitHub Actions, GitLab CI, Jenkins, CircleCI, build pipeline, or continuous integration/delivery?
      - Does it mention pull request attacks, `pull_request_target`, workflow abuse, or GITHUB_TOKEN exploitation?
      - Does it mention self-hosted runners, runner compromise, matrix-build injection, or cache poisoning?
      - Does it mention dependency confusion, typo-squatting, artifact poisoning, malicious packages in CI, or supply chain attacks through build pipelines?
      - Does it mention third-party action pinning, orb poisoning, shared-library injection, or pipeline-as-code tampering?
      - Key boundary: if the request targets a deployed web app (not the pipeline that builds it), use the appropriate web skill instead.""",
    'browser_exploitation': """   - **browser_exploitation**:
      - Does the request mention Electron, Electron IPC, contextBridge, preload script, or desktop apps built with web technologies?
      - Does it mention Chrome extensions, extension message-passing, extension API abuse, or extension permissions?
      - Does it mention DevTools protocol, remote debugging port, Chrome headless, or Puppeteer?
      - Does it mention DOM clobbering, service worker interception, postMessage exploitation, or SameSite cookie bypass?
      - Does it mention browser-in-the-browser (BitB), browser UI spoofing, or web-to-native bridge exploitation?
      - Key boundary: if the request is about injecting JS into a web page (not exploiting the browser/Electron host), use `xss` instead.""",
    'container_k8s': """   - **container_k8s**:
      - Does the request mention Docker, container, Kubernetes, K8s, pods, kubelet, etcd, or container orchestration?
      - Does it mention container registry scanning, image layer analysis, image history inspection, or registry secrets extraction?
      - Does it mention Kubernetes RBAC, ClusterRole, service account tokens, RoleBinding, or privilege escalation within K8s?
      - Does it mention pod breakout, container escape, privileged containers, CAP_SYS_ADMIN, hostPath mounts, or namespace escape?
      - Does it mention admission controller webhooks, PodSecurityPolicy, PodSecurity, or kubeconfig extraction?
      - Key boundary: if the agent already has a shell inside a container and needs to escape, use the `docker_escape` post-exploitation skill instead.""",
    'hybrid_identity': """   - **hybrid_identity**:
      - Does the request mention AD FS, ADFS, federation, federated identity, or Active Directory Federation Services?
      - Does it mention Azure AD Connect, AADC, pass-through authentication, PTA, or Entra ID synchronization?
      - Does it mention Kerberos delegation (constrained, unconstrained, resource-based), S4U2Self, S4U2Proxy, or RBCD?
      - Does it mention token theft, token manipulation, SAML assertion signing, or federated trust attacks?
      - Does it mention cross-forest trust, SIDHistory, Bronze Bit, device code phishing, or consent grant abuse?
      - Does it mention PRT (Primary Refresh Token), cloud-to-on-prem token broker, or hybrid identity bridging?
      - Key boundary: if the request is about on-prem AD attacks without federation (Kerberoasting, AS-REP roasting, DCSync), use `ad_kill_chain` or BloodHound skills instead.""",
    'ad_kill_chain': """   - **ad_kill_chain**:
      - Does the request mention Active Directory, AD, BloodHound, domain admin, DA, or on-prem Windows domain compromise?
      - Does it mention Kerberoasting, AS-REP roasting, password spraying, or credential attacks against AD?
      - Does it mention NTLM relay, pass-the-hash, PtH, overpass-the-hash, or lateral movement?
      - Does it mention DCSync, Golden Ticket, Silver Ticket, DCShadow, or domain dominance?
      - Does it mention delegation abuse, unconstrained delegation, constrained delegation, RBCD, S4U2Self, S4U2Proxy?
      - Does it mention AD CS, ESC1-ESC13, certipy-ad, or certificate abuse in AD?
      - Does it mention impacket, netexec, nxc, enum4linux, kerbrute, or bloodhound-python?
      - Key boundary: if the request is about federation, Entra ID, Azure AD Connect, or cloud identity bridging, use `hybrid_identity` instead.""",
    'cloud_infra_exploitation': """   - **cloud_infra_exploitation**:
      - Does the request mention AWS, GCP, Azure, cloud, IAM, S3, Lambda, EC2 metadata, or cloud-native services?
      - Does it mention instance metadata service (IMDS, IMDSv2), service account, or managed identity?
      - Does it mention cloud storage bucket enumeration, public S3 bucket, or cloud credential theft?
      - Does it mention cross-account role assumption, privilege escalation in the cloud, or serverless abuse?
      - Does it mention AWS STS, Azure ARM, GCP IAM, Secrets Manager, or Key Vault?
      - Key boundary: if the request is about Kubernetes pods, kubelet, or container orchestration, use `container_k8s` instead. If it is about a single SSRF fetch to metadata, use `ssrf` instead.""",
    'api_security_testing': """   - **api_security_testing**:
      - Does the request mention API, REST API, GraphQL, gRPC, swagger, openapi, or endpoint testing?
      - Does it mention IDOR, BOLA, BFLA, broken object level authorization, or broken function level authorization?
      - Does it mention JWT attacks, OAuth2 abuse, API key leakage, or token manipulation?
      - Does it mention GraphQL introspection, batching, query depth, or field suggestions?
      - Does it mention mass assignment, rate-limit bypass, or API versioning issues?
      - Does it mention graphqlmap, graphql-cop, jwt_tool, or API-specific scanners?
      - Key boundary: if the request is specifically about SQL injection, XSS, SSRF, or RCE in API parameters, use the respective primitive skill instead. This skill is for API design/logic flaws.""",
    'supply_chain_poisoning': """   - **supply_chain_poisoning**:
      - Does the request mention supply chain, dependency confusion, typo-squatting, or malicious package?
      - Does it mention npm, pip, PyPI, maven, nuget, cargo, composer, package registry, or package manager?
      - Does it mention manifest poisoning, lockfile tampering, SBOM, or package signature bypass?
      - Does it mention publishing a package to a registry, or exploiting dependency resolution?
      - Key boundary: if the request is about CI/CD pipeline infrastructure (GitHub Actions, Jenkins runners, workflow abuse), use `cicd_pipeline` instead. This skill targets the dependencies and artifacts, not the build infrastructure.""",
    'domain_takeover': """   - **domain_takeover**:
      - Does the request mention subdomain takeover, domain takeover, DNS hijack, or dangling CNAME?
      - Does it mention expired domain, nameserver delegation, NS record hijack, or domain re-registration?
      - Does it mention S3 bucket takeover, CloudFront takeover, GitHub Pages takeover, or Azure App Service takeover?
      - Does it mention DNS misconfiguration, wildcard DNS, SPF, DMARC, DKIM, or email spoofing?
      - Does it mention subzy, dnsx, subdomain enumeration, or DNS reconnaissance?
      - Key boundary: if the request is about general subdomain discovery for attack surface mapping without takeover intent, use `recon-unclassified`. This skill is specifically about acquiring control of a domain or subdomain.""",
    'attack_surface_mapping': """   - **attack_surface_mapping**:
      - Does the request mention attack surface mapping, domain reconnaissance, asset inventory, or comprehensive enumeration of a domain?
      - Does it mention subdomain discovery, passive OSINT, certificate transparency, or ASN mapping?
      - Does it mention port scanning, service fingerprinting, technology detection, or web crawling across a domain?
      - Does it mention API discovery, endpoint enumeration, parameter discovery, or JavaScript analysis?
      - Does it mention combining multiple recon tools (subfinder, amass, httpx, katana, nuclei) into a unified inventory?
      - Key boundary: if the request focuses ONLY on exposed/vulnerable assets (open databases, public buckets), use `infrastructure_exposure_analysis` instead. If it focuses on DNS control acquisition, use `domain_takeover`.""",
    'subdomain_reconnaissance': """   - **subdomain_reconnaissance**:
      - Does the request mention subdomain enumeration, subdomain discovery, or subdomain brute-force?
      - Does it mention certificate transparency (crt.sh), passive DNS, or subdomain OSINT?
      - Does it mention altdns, dnsgen, massdns, dnsx, subfinder, or amass specifically for subdomain finding?
      - Does it mention subdomain permutation, dictionary brute-force, or zone transfer attempts?
      - Does it mention CNAME analysis, dangling CNAME detection, or subdomain takeover reconnaissance?
      - Key boundary: if the request is about comprehensive asset inventory (ports, services, APIs), use `attack_surface_mapping`. If it focuses on acquiring DNS control, use `domain_takeover`. This skill is specifically about discovering and validating subdomains.""",
    'web_application_reconnaissance': """   - **web_application_reconnaissance**:
      - Does the request mention web application reconnaissance, endpoint discovery, or directory brute-force?
      - Does it mention technology fingerprinting (Wappalyzer, WhatWeb), WAF detection, or server identification?
      - Does it mention JavaScript analysis, jsluice, LinkFinder, or extracting endpoints from JS bundles?
      - Does it mention form mapping, input vector discovery, or hidden parameter enumeration?
      - Does it mention HTML comment analysis, source map recovery, or developer hint discovery?
      - Key boundary: if the request is about broad domain asset inventory, use `attack_surface_mapping`. If it focuses on testing API security flaws, use `api_security_testing`. This skill maps web app internals for later exploitation.""",
    'email_security_assessment': """   - **email_security_assessment**:
      - Does the request mention email security, SPF, DMARC, DKIM, MX records, or mail infrastructure?
      - Does it mention email spoofing, open relay, SMTP testing, or mailbox enumeration?
      - Does it mention VRFY, RCPT TO, SMTP banner analysis, or MTA testing?
      - Does it mention email header injection, Bcc injection, or contact form abuse?
      - Does it mention BEC, business email compromise, lookalike domains, or executive impersonation?
      - Does it mention MTA-STS, TLS-RPT, BIMI, or email authentication protocols?
      - Key boundary: if the request is about creating phishing payloads or social engineering emails, use `phishing_social_engineering`. This skill tests the domain's email security CONFIGURATION.""",
    'web_cache_poisoning': """   - **web_cache_poisoning**:
      - Does the request mention cache poisoning, web cache, CDN, cache deception, or cache key manipulation?
      - Does it mention unkeyed headers, X-Forwarded-Host, or header-based poisoning?
      - Does it mention parameter cloaking, cache busting, or cache bypass?
      - Does it mention Cloudflare, Fastly, Akamai, Varnish, or CloudFront cache behavior?
      - Does it mention cache hit/miss, Age header, Vary header, or Cache-Control analysis?
      - Key boundary: if the request is about XSS delivered via cache, use `xss`. If it's about forcing the server to make internal requests, use `ssrf`. This skill targets the cache layer itself.""",
    'transport_security_assessment': """   - **transport_security_assessment**:
      - Does the request mention TLS, SSL, transport security, certificate, or cipher suite analysis?
      - Does it mention testssl, TLS version downgrade, POODLE, BEAST, CRIME, Logjam, or Heartbleed?
      - Does it mention HSTS, certificate pinning, OCSP, certificate transparency, or Expect-CT?
      - Does it mention weak ciphers, forward secrecy, RSA key exchange, or DH parameters?
      - Does it mention certificate chain validation, SAN coverage, or wildcard certificate abuse?
      - Key boundary: if the request is about scanning for open ports or services, use `attack_surface_mapping`. If it's about exploiting a specific TLS CVE with Metasploit, use `cve_exploit`. This skill is configuration-focused transport-layer assessment.""",
    'infrastructure_exposure_analysis': """   - **infrastructure_exposure_analysis**:
      - Does the request mention exposed infrastructure, open database, public bucket, shadow IT, or orphaned assets?
      - Does it mention unauthenticated ElasticSearch, MongoDB, Redis, or exposed admin panels?
      - Does it mention public S3 buckets, GCS buckets, Azure Blob, or open cloud storage?
      - Does it mention exposed .git directories, source code leaks, backup files, or .env exposure?
      - Does it mention Swagger/OpenAPI docs without auth, GraphQL introspection, or unauthenticated APIs?
      - Does it mention Jenkins, Grafana, Kibana, phpMyAdmin, or Docker registry exposure?
      - Key boundary: if the request is about comprehensive asset inventory (regardless of exposure), use `attack_surface_mapping`. If it requires cloud credentials to exploit, use `cloud_infra_exploitation`. This skill discovers exposed assets from the outside.""",
}


def build_classification_prompt(objective: str) -> str:
    """Build a dynamic classification prompt based on enabled skills.

    Only includes sections for enabled built-in skills and any enabled user skills.
    """
    enabled_builtins = get_enabled_builtin_skills()
    enabled_user_skills = get_enabled_user_skills()

    # RoE enforcement: exclude skills from classification when RoE prohibits them
    if get_setting('ROE_ENABLED', False):
        if not get_setting('ROE_ALLOW_DOS', False):
            enabled_builtins.discard('denial_of_service')
        if not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False):
            enabled_builtins.discard('brute_force_credential_guess')
        if not get_setting('ROE_ALLOW_SOCIAL_ENGINEERING', False):
            enabled_builtins.discard('phishing_social_engineering')

    # --- Header ---
    parts = [
        "You are classifying a penetration testing request to determine:\n"
        "1. The required PHASE (informational vs exploitation)\n"
        "2. The ATTACK SKILL TYPE (for exploitation requests only)\n"
    ]

    # --- Phase Types (always included) ---
    parts.append("""## Phase Types

### informational
- Reconnaissance, OSINT, information gathering
- Querying the graph database for targets, vulnerabilities, services
- Scanning and enumeration without exploitation
- Example requests:
  - "What vulnerabilities exist on 10.0.0.5?"
  - "Show me all open ports on the target"
  - "What services are running?"
  - "Query the graph for CVEs"
  - "Scan the network"
  - "What technologies are used?"

### exploitation
- Active exploitation of vulnerabilities
- Brute force / credential attacks
- Generating payloads, reverse shells, or delivery mechanisms for target user execution
- Setting up handlers, listeners, or delivery servers
- Any request that involves gaining unauthorized access
- Example requests:
  - "Exploit CVE-2021-41773"
  - "Brute force SSH"
  - "Try to crack the password"
  - "Pwn the target"
  - "Try SQL injection on the web app"
  - "Generate a reverse shell payload"
  - "Create a malicious Word document"
  - "Set up a web delivery attack"
""")

    # --- Attack Skill Types ---
    parts.append("## Attack Skill Types (ONLY for exploitation phase)\n")

    # Built-in skills (only enabled ones)
    for skill_id in ['phishing_social_engineering', 'brute_force_credential_guess', 'cve_exploit', 'denial_of_service', 'sql_injection', 'xss', 'ssrf', 'rce', 'path_traversal', 'llm_security', 'cicd_pipeline', 'browser_exploitation', 'container_k8s', 'hybrid_identity', 'ad_kill_chain', 'cloud_infra_exploitation', 'api_security_testing', 'supply_chain_poisoning', 'domain_takeover', 'attack_surface_mapping', 'subdomain_reconnaissance', 'email_security_assessment', 'web_cache_poisoning', 'web_application_reconnaissance', 'transport_security_assessment', 'infrastructure_exposure_analysis']:
        if skill_id in enabled_builtins:
            section_text, _, _ = _BUILTIN_SKILL_MAP[skill_id]
            parts.append(section_text)

    # User skills — use description if available, otherwise first 500 chars of content
    for skill in enabled_user_skills:
        preview = skill.get('description') or skill['content'][:500]
        if not skill.get('description') and len(skill['content']) > 500:
            preview += "..."
        parts.append(f'### user_skill:{skill["id"]}\n'
                     f'- User-defined attack skill: **{skill["name"]}**\n'
                     f'- Skill description:\n{preview}\n')

    # Unclassified (always included)
    parts.append(_UNCLASSIFIED_SECTION)

    # --- User Request ---
    parts.append(f"## User Request\n{objective}\n")

    # --- Classification Instructions ---
    parts.append("## Instructions\nClassify the user's request:\n")
    parts.append("1. First determine the REQUIRED PHASE:\n"
                 '   - Is this a reconnaissance/information gathering request? -> "informational"\n'
                 '   - Is this an active attack/exploitation request? -> "exploitation"\n')

    parts.append("2. Determine the AGENT SKILL TYPE that **best matches** the request — regardless of phase. "
                 "Even informational requests have a skill type (e.g., 'scan for SQLi' → sql_injection, "
                 "'brute force SSH' → brute_force_credential_guess). Pick the one whose criteria fit most closely:\n")

    # Built-in skill classification criteria
    builtin_skill_ids = ['phishing_social_engineering', 'brute_force_credential_guess', 'cve_exploit', 'denial_of_service', 'sql_injection', 'xss', 'ssrf', 'rce', 'path_traversal', 'llm_security', 'cicd_pipeline', 'browser_exploitation', 'container_k8s', 'hybrid_identity']
    for skill_id in builtin_skill_ids:
        if skill_id in enabled_builtins:
            parts.append(_CLASSIFICATION_INSTRUCTIONS[skill_id])

    # User skills classification criteria
    for skill in enabled_user_skills:
        parts.append(f'   - **user_skill:{skill["id"]}** ("{skill["name"]}"):\n'
                     f'      - Does the request match the workflow described in the "{skill["name"]}" skill?')

    # Unclassified
    parts.append("   - **<descriptive_term>-unclassified**:\n"
                 "      - Does the request describe a specific attack technique that doesn't match any of the above?\n"
                 "      - For general reconnaissance with no specific attack intent (e.g., 'show attack surface', "
                 "'what vulnerabilities exist'), use **recon-unclassified**")

    default_type = "cve_exploit" if "cve_exploit" in enabled_builtins else "recon-unclassified"
    parts.append(f'\n   If truly unclear (e.g., vague "hack the target"), default to "{default_type}".\n')

    parts.append("3. Extract TARGET HINTS from the request (best-effort, used for graph linking):\n"
                 '   - target_host: IP address or hostname mentioned (e.g., "10.0.0.5", "www.example.com"). null if none found.\n'
                 '   - target_port: port number mentioned (e.g., 8080, 443). null if none found.\n'
                 '   - target_cves: list of CVE IDs mentioned (e.g., ["CVE-2021-41773"]). Empty list if none found.\n')

    # --- Build valid attack_path_type values for JSON schema ---
    valid_types = []
    for skill_id in builtin_skill_ids:
        if skill_id in enabled_builtins:
            valid_types.append(f'"{skill_id}"')
    for skill in enabled_user_skills:
        valid_types.append(f'"user_skill:{skill["id"]}"')
    valid_types.append('"<descriptive_term>-unclassified"')

    parts.append(f"""Output valid JSON matching this schema:

```json
{{{{
  "required_phase": "informational" | "exploitation",
  "attack_path_type": {' | '.join(valid_types)},
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of the classification",
  "detected_service": "ssh" | "ftp" | "mysql" | "mssql" | "postgres" | "smb" | "rdp" | "vnc" | "telnet" | "tomcat" | "http" | null,
  "target_host": "10.0.0.5" | "www.example.com" | null,
  "target_port": 8080 | null,
  "target_cves": ["CVE-2021-41773"] | []
}}}}
```

Notes:
- `required_phase` determines if this is reconnaissance ("informational") or active attack ("exploitation")
- `attack_path_type` MUST always be set — it identifies which agent skill workflow to use, regardless of phase
- For general recon with no specific attack technique, use "recon-unclassified"
- For unclassified attack techniques, use a descriptive term followed by "-unclassified" (e.g., "ssrf-unclassified", "file_upload-unclassified")
- `detected_service` should only be set for brute_force_credential_guess, null otherwise
- `confidence` should be 0.9+ if the intent is very clear, 0.6-0.8 if somewhat ambiguous
- `target_host`, `target_port`, `target_cves` are best-effort extraction — null/empty if not mentioned""")

    return "\n".join(parts)


# Keep backward-compatible constant for any code that still references it directly
# (uses all skills enabled as default)
ATTACK_PATH_CLASSIFICATION_PROMPT = None  # Use build_classification_prompt() instead

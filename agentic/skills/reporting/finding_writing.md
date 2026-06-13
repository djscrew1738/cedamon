---
name: Finding Writing & Report Structure
description: Standards for writing penetration testing findings, including risk ratings, evidence requirements, remediation guidance, and report structure
---

# Finding Writing & Report Structure

Pull this skill when you need to write up a finding for a vulnerability or security issue discovered during testing. This skill ensures consistency, completeness, and professionalism in reporting.

## Finding anatomy

Every finding should contain these sections in this order:

```
[Title] — Short, descriptive. e.g., "SQL Injection in Login Parameter"

┌─────────────────────────────────────────────────┐
│ Severity: Critical/High/Medium/Low/Info          │
│ Status:  Open / Confirmed / Fixed / Accepted     │
│ CVSS:    X.X (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) │
└─────────────────────────────────────────────────┘

Description
  Clear explanation of the vulnerability in business context.
  What is it, where was it found, and why does it matter?

Steps to Reproduce
  Numbered, step-by-step instructions that anyone can follow
  to independently reproduce the finding.

Proof of Concept (PoC)
  Actual commands run, payloads used, and the output received.
  Include screenshots or terminal output blocks.

Impact
  What an attacker could achieve by exploiting this finding.
  Be specific — don't just say "data exposure"; say "access to
  all user records in the database (10,000+ rows including PII)."

Remediation
  Clear, actionable fix instructions. Short-term workaround and
  long-term fix if different.

References
  Links to CVE, CWE, OWASP, vendor documentation, etc.
```

## Risk rating guide

Using CVSS 3.1 scoring:

| Severity | Score | Typical finding type |
|----------|-------|---------------------|
| Critical | 9.0-10.0 | RCE, SQLi with data extraction, authentication bypass |
| High | 7.0-8.9 | Privilege escalation, SSRF with cloud metadata access, XSS (stored) |
| Medium | 4.0-6.9 | XSS (reflected), open redirect, information disclosure |
| Low | 0.1-3.9 | Missing security headers, verbose error messages, minor info leak |
| Informational | 0.0 | Software version disclosure, internal IP disclosure |

### CVSS quick calculator
```python
# Use execute_code to compute CVSS
# AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H  ->  10.0 (Critical)
# AV:A/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:N  ->  1.4 (Low)
```

## Evidence collection standards

### Screenshots
```bash
# Full-screen capture
import -window root finding_001_desktop.png

# Specific window
import -window $(xdotool search --name "Firefox" | head -1) finding_001_burp.png

# Terminal recording for PoC
script -q /tmp/poc_session.log
# ... run commands ...
exit
cat /tmp/poc_session.log  # Use this in the finding
```

### Terminal output
```
$ command output — include the full command and response, trimmed of irrelevant lines

$ curl -v http://target/vuln?param=payload
< HTTP/1.1 200 OK
< ...response body...
```

### Request/response pairs
```
=== REQUEST ===
GET /admin HTTP/1.1
Host: target.com
Cookie: session=...

=== RESPONSE ===
HTTP/1.1 200 OK
Content-Type: text/html

<html>...admin panel...</html>
```

## Report structure

A full penetration test report should follow this structure:

```
1. EXECUTIVE SUMMARY
   1.1 Background
   1.2 Scope
   1.3 Timeline
   1.4 Overall Risk Rating
   1.5 Key Findings Summary (3-5 bullet points)

2. TECHNICAL FINDINGS
   2.1 Critical Findings
   2.2 High Findings
   2.3 Medium Findings
   2.4 Low Findings
   2.5 Informational

3. SCOPE & METHODOLOGY
   3.1 In-scope targets
   3.2 Testing methodology (e.g., OSSTMM, OWASP WSTG)
   3.3 Tools used
   3.4 Limitations / Out of scope

4. REMEDIATION SUMMARY
   4.1 Quick wins (low effort, high impact)
   4.2 Strategic recommendations
   4.3 Prioritized action plan

A. APPENDIX — Detailed PoC logs
B. APPENDIX — Third-party scan outputs
C. APPENDIX — Glossary
```

## Severity determination decision tree

```
Is the finding remotely exploitable without auth?
├── YES → Is it RCE, SQLi, or auth bypass?
│   ├── YES → Critical
│   └── NO → High
└── NO → Does it require authenticated access?
    ├── YES → Does it leak sensitive data or allow privilege escalation?
    │   ├── YES → High/Medium
    │   └── NO → Medium/Low
    └── NO → Requires physical access or user interaction?
        ├── YES → Medium
        └── NO → Low/Info
```

## Common writing pitfalls

| Pitfall | Fix |
|---------|-----|
| "The application is vulnerable to XSS" | "The search functionality at /search reflects unvalidated user input in the response without encoding, allowing execution of arbitrary JavaScript in the victim's browser." |
| "High risk — data exposure" | "Critical risk — unauthenticated access to the user database (10,000 records) via SQL injection in the login endpoint, exposing PII including email, phone, and hashed passwords." |
| "Fix input validation" | "Implement parameterized queries for all database operations in the login handler. Validate that the `username` parameter matches a strict alphanumeric pattern with a maximum length of 64 characters." |
| No remediation priority | Always state the short-term fix immediately needed, plus the long-term architectural fix. |
| Generic instead of specific | Include the exact URL, parameter, payload, and response snippet that confirms the vulnerability. |

## Validation shape

A finding is complete when:
- [ ] Title clearly states the vulnerability type and location
- [ ] Severity is rated (with CVSS vector if possible)
- [ ] Description explains the issue in business + technical terms
- [ ] Steps to Reproduce are numbered and independently replicable
- [ ] PoC includes actual commands, payloads, and responses
- [ ] Impact explains the real-world consequence, not just CVE text
- [ ] Remediation is actionable (short-term + long-term)
- [ ] Finding is reproducible from the written instructions alone

## Hand-off

- For grouping related findings: Compile into a report following the structure above
- For creating executive summaries: `-> /skill reporting/executive_summary`
- For collecting remediation metrics: Note count of findings per severity for trending

## Pro tips

- **One finding, one vulnerability**: Don't combine separate issues into a single finding. A critical SQLi and a low missing header need separate entries.
- **CVSS is a tool, not a rule**: If the CVSS score doesn't match the business impact, adjust. A medium-CVSS finding on a crown-jewel system may be high in practice.
- **Reproduce before writing**: If you cannot reproduce the finding from your own notes, rewrite until you can. The report must stand independently.
- **Redact sensitive data**: Never include real passwords, PII, or session tokens in the report. Replace with `<REDACTED>` or example data.
- **Screenshots expire**: Include the URL bar, date, and relevant context in every screenshot. A screenshot of a blank admin page without the URL is useless.

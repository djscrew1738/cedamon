---
name: Masscan
description: High-speed asynchronous port scanning capable of scanning the entire internet in minutes, used for large-scale port discovery
---

# Masscan

Pull this skill when you need to scan large IP ranges or the entire internet for open ports. Masscan is the fastest port scanner available — it can scan the full IPv4 internet on a single port in ~5 minutes under ideal conditions.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Full port scan (all 65535) | `execute_masscan` | Use `-p1-65535` |
| Single port across large range | `execute_masscan` | Best use case — fast |
| Top N ports | `execute_masscan` | Use `--top-ports 1000` |
| Service detection | `execute_masscan` | `--banners` flag |
| Output to file | `execute_masscan` | `-oJ`, `-oL`, `-oX`, `-oG` |

## Primer

Masscan uses asynchronous TCP SYN scanning (no full handshake). It sends SYN packets and listens for SYN-ACK responses, then sends RST. This stateless design allows it to scan at 10+ million packets per second.

| vs Nmap | Masscan | Nmap |
|---------|---------|------|
| Speed | 10M+ pps (full internet in minutes) | ~100 pps per target | 
| Accuracy | Good (some false positives) | Excellent (retry + service detec) |
| Detail | IP + port + banner only | Scripting, OS detection, full service scan |
| Best for | Large-scale discovery | Targeted follow-up |

## Workflow: masscan → nmap

The standard pattern is: masscan for discovery → nmap for detailed analysis.

```bash
# Step 1: Masscan to find live hosts/ports
execute_masscan 192.168.0.0/16 -p80,443,22,3389,8080,8443 --rate=1000 -oL masscan.txt

# Step 2: Masscan output to Nmap targets
awk '/open tcp/ {print $4, $3}' masscan.txt | sort -u | \
  while read ip port; do echo "$ip:$port" >> masscan_targets.txt; done

# Step 3: Nmap detailed scan
execute_nmap -sV -sC -iL masscan_targets.txt -oA detailed_scan
```

## Key flags

| Flag | Purpose |
|------|---------|
| `-p` | Port range (`-p80,443` or `-p1-65535`) |
| `--top-ports N` | Scan top N most common ports |
| `--rate` | Packets per second (start at 1000, increase carefully) |
| `--banners` | Grab service banners |
| `--excludefile` | File with IP ranges to exclude |
| `--resume` | Resume from previous scan |
| `-oJ` | JSON output |
| `-oL` | One-line-per-result output (parsable) |
| `-oX` | XML output |
| `-oG` | Greppable output |
| `--adapter-ip` | Source IP for scanning (multi-homed hosts) |
| `--adapter-port` | Source port range |
| `--ttl` | IP TTL for outbound packets |
| `--wait` | Seconds to wait for responses after scan ends |
| `--retries` | Number of retry attempts |

## Rate limit guidance

| Rate | Use case | Caution |
|------|----------|---------|
| 100 pps | Small internal network (/24) | Safe |
| 1,000 pps | /16 subnet | Safe with good network |
| 10,000 pps | /8 subnet or larger | May trigger ISP alerts |
| 100,000 pps | Internet-wide scan | Will get noticed. Use responsibly |
| 1,000,000+ pps | Full internet scan | Requires 10Gbps link. Professional setup only |

## Recipes

### Scan top 1000 ports on a /16 internal subnet
```bash
execute_masscan 10.0.0.0/16 --top-ports 1000 --rate=10000 -oJ internal_scan.json
```

### Scan specific ports on a CIDR block
```bash
execute_masscan 203.0.113.0/24 -p22,80,443,8443,8080,3306,5432,6379,27017 \
  --rate=1000 -oL found.txt
```

### Full port scan on a small subnet
```bash
execute_masscan 192.168.1.0/24 -p1-65535 --rate=100000 -oJ full_scan.json
```

### Banner grabbing on found ports
```bash
execute_masscan 192.168.1.0/24 -p80,443 --banners --rate=1000
```

### Exclude known ranges (ISP, cloud providers)
```bash
echo "10.0.0.0/8" > excludes.txt
echo "172.16.0.0/12" >> excludes.txt
echo "192.168.0.0/16" >> excludes.txt
execute_masscan 0.0.0.0/0 -p443 --rate=100000 --excludefile excludes.txt
```

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| "FAIL: failed to detect IP for interface" | Specify adapter with `--adapter-ip YOUR_IP` |
| All ports show "filtered" | Need raw socket permissions (root/sudo) |
| Packets not being sent | `--rate` too high for hardware. Check `--adapter` is correct interface |
| Too many results | Masscan has no service detection (unless `--banners`). Always validate with nmap |
| ISP alerted | Reduce rate drastically, or use a VPS with explicit scanning authorization |
| Packet loss with virtual NICs | Set `--rate` lower; virtual adapters drop packets at high rates |

## Output format examples

```bash
# -oL (one line, most parseable):
# open tcp 80 203.0.113.5 1710098765
# open tcp 443 203.0.113.5 1710098766

# -oJ (JSON):
# [{"ip":"203.0.113.5","ports":[{"port":80,"proto":"tcp","status":"open","reason":"syn-ack","ttl":55}]}]

# Parse -oL to nmargable targets:
awk '/open tcp/ {print $4":"$3}' masscan.txt > nmap_targets.txt
```

## Resource usage

| Scan scope | Rate | Time estimate | Memory |
|------------|------|---------------|--------|
| /24, top 100 ports | 10,000 pps | ~10 seconds | Minimal |
| /16, top 1000 ports | 100,000 pps | ~5 minutes | Low |
| /8, 1 port | 1,000,000 pps | ~5 minutes | Moderate |
| All IPv4, 1 port | 1,000,000 pps | ~5 hours | High |

## Hand-off

- After masscan identifies open ports: `-> /skill/tooling/nmap` for detailed target scanning
- For web ports (80,443,8080,8443): `-> /skill/tooling/httpx` for HTTP probing
- For discovered databases (3306,5432,6379,27017): Check default creds or weak auth
- For internal scan results: `-> /skill/network/arp_spoofing` if ARP discovered hosts in the first place
- For RDP (3389): `-> /skill/tooling/hydra` for brute-force with `rdp://`

## Pro tips

- **Masscan for discovery, nmap for detail**: Never use masscan for service version detection or script scanning. Masscan finds needles, nmap inspects them.
- **Rate is the only knob that matters**: Start at 1000 and double until packet loss appears. Back off 50% from the loss threshold for reliable results. On consumer hardware with gigabit Ethernet, 50K-100K pps is typical.
- **Exclude your own IP**: Always exclude your scanning box's IP range to avoid SYN-ACK depleting your own connection table.
- **Use resume for long scans**: Masscan saves progress periodically. Use `--resume` to continue interrupted scans without re-scanning completed ranges.
- **The `--banners` flag is slow**: It waits for banners to arrive, turning the stateless scan into a stateful one. Use it selectively on small ranges, not internet-scale sweeps.

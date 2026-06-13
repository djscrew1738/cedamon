---
name: Gobuster
description: Directory/file enumeration, DNS subdomain brute-forcing, virtual host discovery, and S3 bucket enumeration using GoBuster
---

# Gobuster

Pull this skill for brute-forcing directories, DNS subdomains, virtual hosts, or S3 buckets. Gobuster is the fastest directory brute-forcer available and supports multiple modes.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Directory/file brute-force | `kali_shell` — `gobuster dir` | Fastest dir enumeration |
| DNS subdomain brute-force | `kali_shell` — `gobuster dns` | Alternative to amass brute |
| Vhost discovery | `kali_shell` — `gobuster vhost` | Find hidden virtual hosts |
| S3 bucket enumeration | `kali_shell` — `gobuster s3` | Public S3 bucket discovery |
| Custom extensions | `kali_shell` — `gobuster dir -x` | Append php,asp,jsp,etc |
| Output to file | `kali_shell` — `gobuster dir -o` | Standard output |

## Primer

Gobuster has four operating modes:

| Mode | Use case | Example |
|------|----------|---------|
| `dir` | Find hidden files and directories | `gobuster dir -u https://target.com -w wordlist.txt` |
| `dns` | Discover subdomains | `gobuster dns -d target.com -w subdomains.txt` |
| `vhost` | Discover virtual hosts | `gobuster vhost -u https://target.com -w vhosts.txt` |
| `s3` | Find S3 buckets | `gobuster s3 -w bucket-names.txt` |

## Dir mode

```bash
# Basic directory brute-force
gobuster dir -u https://target.com -w /wordlists/common.txt

# With file extensions (common web languages)
gobuster dir -u https://target.com -w /wordlists/common.txt -x php,asp,aspx,jsp,html,txt

# With status code filtering (hide 404s, show everything else)
gobuster dir -u https://target.com -w /wordlists/common.txt -s 200,204,301,302,307,401,403

# Exclude certain status codes
gobuster dir -u https://target.com -w /wordlists/common.txt --exclude-length 0

# Follow redirects
gobuster dir -u https://target.com -w /wordlists/common.txt -r

# Add authentication headers
gobuster dir -u https://target.com -w /wordlists/common.txt \
  -H "Authorization: Bearer eyJ..."

# With response size exclusion (filter out noise pages)
gobuster dir -u https://target.com -w /wordlists/common.txt \
  --exclude-length 1234,5678
```

### Dir key flags

| Flag | Purpose |
|------|---------|
| `-u` | Target URL |
| `-w` | Wordlist path |
| `-x` | File extensions to try (`-x php,html`) |
| `-s` | Status codes to include (`-s 200,301,401`) |
| `-r` | Follow redirects |
| `-H` | Custom headers |
| `-t` | Threads (default 10, max ~200) |
| `-o` | Output file |
| `-k` | Skip TLS verification |
| `-f` | Append `/` to directory requests |
| `-n` | Don't follow redirects |
| `-e` | Expanded mode (show full URL) |
| `--no-color` | Plain output for piping |
| `--exclude-length` | Exclude responses of specific size |

## DNS mode

```bash
# Basic subdomain brute-force
gobuster dns -d target.com -w /wordlists/subdomains.txt

# With wildcard detection
gobuster dns -d target.com -w /wordlists/subdomains.txt --wildcard

# With custom DNS resolver
gobuster dns -d target.com -w /wordlists/subdomains.txt -r 8.8.8.8

# Output resolvable subdomains only
gobuster dns -d target.com -w /wordlists/subdomains.txt -o resolved.txt
```

### DNS key flags

| Flag | Purpose |
|------|---------|
| `-d` | Target domain |
| `-w` | Wordlist path |
| `-r` | Custom DNS resolver IP |
| `--wildcard` | Detect and handle wildcard DNS |
| `-o` | Output file |
| `-t` | Threads (default 10) |

## Vhost mode

```bash
# Discover virtual hosts (different from DNS subdomains)
gobuster vhost -u https://target.com -w /wordlists/vhosts.txt

# With User-Agent to avoid blocking
gobuster vhost -u https://target.com -w /wordlists/vhosts.txt \
  -H "User-Agent: Mozilla/5.0"

# Output discovered hosts
gobuster vhost -u https://target.com -w /wordlists/vhosts.txt -o vhosts.txt
```

## S3 mode

```bash
# Discover S3 buckets
gobuster s3 -w /wordlists/bucket-names.txt

# Output discovered buckets
gobuster s3 -w /wordlists/bucket-names.txt -o buckets.txt
```

## Wordlist recommendations

| Type | Recommended wordlist | Size |
|------|---------------------|------|
| Dir (quick) | `/usr/share/wordlists/dirb/common.txt` | 4,614 |
| Dir (medium) | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` | 220K |
| Dir (comprehensive) | `/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt` | 62K |
| DNS (top 5000) | Seclists: `Discovery/DNS/subdomains-top1million-5000.txt` | 5K |
| DNS (large) | Seclists: `Discovery/DNS/namelist.txt` | 182K |
| Vhost | Seclists: `Discovery/DNS/subdomains-top1million-20000.txt` | 20K |
| Extensions | `php,asp,aspx,jsp,html,txt,json,xml,bak,old` | Custom |

## Recipes

### Full recon pipeline
```bash
# 1. DNS subdomain discovery
gobuster dns -d target.com -w /wordlists/subdomains.txt -o dns.txt

# 2. Probe live subdomains
cat dns.txt | awk '{print $2}' | execute_httpx -silent -o live.txt

# 3. Directory brute-force on live hosts
while read url; do
  domain=$(echo "$url" | cut -d'/' -f3)
  gobuster dir -u "$url" -w /wordlists/common.txt -x php,html,txt \
    -s 200,301,401,403 -o "gobuster_${domain}.txt"
done < live.txt

# 4. Vhost discovery
gobuster vhost -u https://target.com -w /wordlists/vhosts.txt -o vhosts.txt
```

### API discovery (full paths)
```bash
# Try common API path prefixes
gobuster dir -u https://target.com -w /wordlists/api-paths.txt \
  -x json,xml -s 200,401,403,500

# With Bearer auth
gobuster dir -u https://target.com/api/v1 -w /wordlists/api-objects.txt \
  -H "Authorization: Bearer eyJ..." -s 200,401,403
```

### Content discovery with extensions
```bash
# Check for backups and source files
gobuster dir -u https://target.com -w /wordlists/common.txt \
  -x bak,old,php,tar,gz,zip,sql,txt,save,swp \
  -s 200,301,401
```

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| All paths return 200 (false positives) | Use `--exclude-length` matching the default page size, or check for default page hash |
| Rate-limited/blocked | Reduce threads to 10, add request delay with `-t 5` |
| DNS wildcard responses | Use `--wildcard` flag to filter wildcard IPs from results |
| Vhost doesn't find anything | The target may not use vhosts. Try with the IP instead of FQDN. |
| Too slow | Increase threads: `-t 100` for dir, `-t 50` for dns |
| SSL errors | Use `-k` to skip TLS verification for self-signed certs |
| Redirects wasting time | Don't follow redirects unless you need to see redirected status codes |

## Performance comparison (dir mode)

| Threads | Wordlist size | Time (approx) | Notes |
|---------|---------------|---------------|-------|
| 10 | 4,600 (dirb common) | ~30 sec | Safe default |
| 50 | 4,600 | ~5 sec | Good network |
| 100 | 220K (dirbuster medium) | ~5 min | Production target |
| 200 | 220K | ~2-3 min | Very fast network |

## Hand-off

- After finding directories: `-> /skill/tooling/katana` to crawl discovered paths
- After finding API paths: `-> /skill/tooling/ffuf` for parameter fuzzing
- After finding config files (`.bak`, `.sql`, `.tar.gz`): `execute_curl` to download and inspect
- For subdomain discovery alternatives: `-> /skill/tooling/amass`
- For live host probing: `-> /skill/tooling/httpx`

## Pro tips

- **Use specific wordlists**: Don't use a 2M-line wordlist on a /. A 4K common.txt first pass finds 80% of results in 30 seconds. Then use a larger list for depth.
- **Extensions multiply requests**: `-x php,html` triples the request count. Start without extensions, then run short targeted extension scans on interesting paths.
- **DNS vs Vhost**: DNS subdomains point to different IPs (resolved); vhosts point to the same IP but serve different sites (Host header). They find different results — always run both.
- **Exclude-length is your noise filter**: The single most useful flag. Find the response size of the default 404 page and exclude it: `--exclude-length 1234`.
- **Combine with gau for redirection targets**: Use gau to find already-known paths, then gobuster to find the hidden ones. The ratio is usually 20% known / 80% discovered.

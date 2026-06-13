---
name: Hashcat
description: High-performance password hash cracking with GPU/CPU acceleration for over 320 hash types including Windows NTLM, Kerberos, MD5, SHA, bcrypt, and more
---

# Hashcat

Pull this skill when you have password hashes from a dump (secretsdump, Kerberoasting, SQL injection, etc.) and need to recover the plaintext passwords. Hashcat is the fastest hash-cracking tool available.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Crack NT hashes | `execute_code` — `hashcat` | NTLM (-m 1000) |
| Crack Kerberos TGS | `execute_code` — `hashcat` | Kerberoast (-m 13100) |
| Crack ASREP hashes | `execute_code` — `hashcat` | ASREP (-m 18200) |
| Crack MD5/SHA | `execute_code` — `hashcat` | Various modes |
| Crack bcrypt | `execute_code` — `hashcat` | Slow but effective |
| Brute-force (mask) | `execute_code` — `hashcat` | When wordlists fail |
| Rule-based | `execute_code` — `hashcat` | With best64/rules |
| Show cracked results | `execute_code` — `hashcat` | `--show` flag |

## Primer

Hashcat takes input hashes, applies wordlists and rules (or brute-force masks), and tests each candidate against the target hash.

```
Hash file → Hashcat → Cracked.txt
               ↑
         Wordlist + Rules
```

**When to use what:**
| Approach | Speed | Best for |
|----------|-------|----------|
| Wordlist only | Fastest | Common passwords |
| Wordlist + rules | Fast | Mutated versions of common passwords |
| Mask (brute-force) | Slow | Short passwords with known patterns |
| Dictionary + Markov | Moderate | Unknown patterns |

## Hash types (most common)

| Hash type | Mode `-m` | Example | Speed |
|-----------|-----------|---------|-------|
| NTLM | `1000` | Windows password hashes | Very fast (100 GH/s) |
| MD5 | `0` | Various web apps | Very fast |
| SHA1 | `100` | Various | Fast |
| SHA256 | `1400` | Various | Moderate |
| bcrypt | `3200` | Most web app passwords | Slow (10 KH/s) |
| Kerberos TGS | `13100` | Kerberoasting output | Moderate |
| Kerberos AS-REP | `18200` | ASREP roast output | Moderate |
| NetNTLMv2 | `5600` | Captured NTLM challenge | Fast |
| MS-CACHE | `2100` | Domain cached credentials | Moderate |
| PBKDF2 | `10900` | Various | Slow |
| SHA512 ($6$) | `1800` | Linux shadow file | Moderate |

## Basic usage

```bash
# Simple wordlist attack
hashcat -m 1000 hashes.txt rockyou.txt -o cracked.txt

# Wordlist with rules
hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule -o cracked.txt

# Mask attack (brute-force)
hashcat -m 1000 hashes.txt -a 3 ?u?l?l?l?d?d?d?d?d -o cracked.txt
```

## Attack modes

| Mode `-a` | Name | Example |
|-----------|------|---------|
| 0 | Wordlist | `hashcat -a 0 -m 1000 hashes.txt wordlist.txt` |
| 1 | Combination | `hashcat -a 1 -m 1000 hashes.txt wordlist1.txt wordlist2.txt` |
| 3 | Mask (brute-force) | `hashcat -a 3 -m 1000 hashes.txt ?a?a?a?a?a?a?a?a` |
| 6 | Hybrid wordlist + mask | `hashcat -a 6 -m 1000 hashes.txt wordlist.txt ?d?d?d` |
| 7 | Hybrid mask + wordlist | `hashcat -a 7 -m 1000 hashes.txt ?d?d?d wordlist.txt` |

## Mask reference

| Placeholder | Character set |
|-------------|---------------|
| `?l` | abcdefghijklmnopqrstuvwxyz |
| `?u` | ABCDEFGHIJKLMNOPQRSTUVWXYZ |
| `?d` | 0123456789 |
| `?s` | !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ |
| `?a` | `?l?u?d?s` (all) |
| `?b` | 0x00-0xff (all bytes) |

### Custom character sets
```bash
# -1 custom set, -2 second custom set, etc.
hashcat -a 3 -m 1000 hashes.txt -1 ?u?d ?1?l?l?l?l?d?d?d?d
```

### Common masks
```
# 8-digit numeric PIN
?d?d?d?d?d?d?d?d

# Capital + 6 lowercase + 2 digits (standard password pattern)
?u?l?l?l?l?l?l?d?d

# 8-char all (brute-force everything)
?a?a?a?a?a?a?a?a

# Year-based (Company2024)
?u?l?l?l?l?l?l?l?d?d?d?d

# Word + 2 digits (Password12 pattern)
# Use mode 6 for this: -a 6 wordlist.txt ?d?d
```

## Rule files

| Rule file | Purpose |
|-----------|---------|
| `best64.rule` | Most effective 64 rules |
| `d3ad0ne.rule` | Large, aggressive mutations |
| `OneRuleToRuleThemAll.rule` | Community-curated, comprehensive |
| `toggles.rule` | Case toggling |
| `leetspeak.rule` | L33t speak substitutions |

```bash
# Apply rules to wordlist
hashcat -m 1000 hashes.txt wordlist.txt -r best64.rule -r toggles.rule -O
```

## Performance optimization

| Flag | Effect |
|------|--------|
| `-O` | Optimised kernel (enables loop unrolling) |
| `--workload-profile 3` | Highest GPU utilisation (default) |
| `--opencl-device-types GPU` | Only use GPU (not CPU) |
| `-d 1` | Select specific device |
| `-n 256` | Increase rule parallelism (GPU dependent) |
| `-u 1024` | Increase loop count (GPU dependent) |

### Speed comparison (NTLM, single RTX 4090)
| Approach | Speed | Time for 5000 hashes |
|----------|-------|---------------------|
| rockyou.txt only | ~200 GH/s | ~2 min |
| rockyou + best64 | ~50 GH/s | ~10 min |
| 8-char mask (?a?a?a?a?a?a?a?a) | ~100 GH/s | ~3 hours (8 char) |
| bcrypt default | ~10 KH/s | ~2 hours per 5000 hashes |

## Recipes

### Cracking NTLM from secretsdump
```bash
# Format from secretsdump: user:uid:LM:NTLM:::
# Extract NTLM only:
cut -d: -f4 hashes.txt > ntlm_only.txt

# Crack with rockyou
hashcat -m 1000 ntlm_only.txt /usr/share/wordlists/rockyou.txt \
  -r best64.rule -O -o cracked.txt

# Show cracked
hashcat -m 1000 ntlm_only.txt --show
```

### Cracking Kerberos TGS hashes
```bash
# Hash format from GetUserSPNs:
# $krb5tgs$23$*user$realm$spn*$hash
hashcat -m 13100 kerberos_hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule -O
```

### Cracking NetNTLMv2 (from responder or mitmproxy)
```bash
hashcat -m 5600 captured_ntlmv2.txt rockyou.txt -r best64.rule
```

### Cracking Linux shadow hashes
```bash
# unshadow passwd shadow > unshadowed.txt
hashcat -m 1800 unshadowed.txt rockyou.txt -r best64.rule
```

## Output format

```bash
# Hashcat: --show
hashcat -m 1000 hashes.txt --show
# Format: hash:password

# Use --username to preserve usernames from input
hashcat -m 1000 hashes.txt rockyou.txt --username -o cracked.txt
```

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| "No device found" | Check GPU drivers: `nvidia-smi` or `rocminfo` |
| "Skipping token" for odd hash format | Check hash format matches mode `-m`. Use `hashid` or `hash-identifier` |
| Too slow | Use `-O`, ensure GPU is selected (`-d 2`), close other GPU apps |
| All hashes cracked but said 0/0 | Hashes were already cracked. Use `--show` to display. |
| "Line-length exception" | Some hash formats have very long lines (Kerberos). This is normal. |
| 0 hashes loaded | Hash mode doesn't match. Double-check the format and mode. |
| GPU out of memory | Fewer threads: `-n 64 -u 256` |

## Cracking strategy priority

```
1. rockyou.txt (wordlist only)          — catches ~30-50% in seconds
2. rockyou.txt + best64.rule            — catches ~50-70% in minutes
3. rockyou.txt + OnRuleToRuleThemAll    — catches ~70-85% in hours
4. Company name mutations (custom list) — catches the remainder
5. Mask attack (7-8 char)               — as a last resort for critical hashes
```

Stop after each phase. Many hashes will crack in step 1 or 2.

## Hand-off

- After cracking hashes: `-> /skill/tooling/impacket` for lateral movement with cracked creds
- For AD access with cracked password: `-> /skill/active_directory/ad_kill_chain`
- For network login brute-force: `-> /skill/tooling/hydra` (online) vs hashcat (offline)
- For LSASS dumping: Before hashcat, you need hashes from secretsdump or lsass minidump

## Pro tips

- **Use `--show` before cracking**: You may already have cracked these hashes. Always check first.
- **Start with rockyou, not rules**: A plain rockyou.txt attack cracks ~30-40% of NTLM hashes in under a minute. Running rules on a 30% hit rate wastes GPU time on the easy ones. Do minimal first.
- **bcrypt/argon2 are slow**: If you're cracking bcrypt ($2b$), expect 10-100 KH/s even on a good GPU. Use targeted wordlists (rockyou only, no rules) and prioritize the most important hashes.
- **Hybrid attacks for modern passwords**: Most people use `Word2024!` or `Company1!` patterns. Mode 6 (hybrid wordlist+mask) with `?d?d?d?d` and `?s` catches these.
- **Hundreds of password mutations are predictable**: 74% of breached passwords follow these 5 patterns: (1) word + year, (2) word + digit, (3) capital + lowercase + digits, (4) season + year, (5) company + number. Tune your rules for these.

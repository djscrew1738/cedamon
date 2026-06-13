---
name: Pretexting & Social Engineering Frameworks
description: Pretext development, target research, communication lures, and social engineering campaign frameworks for authorized social engineering assessments
---

# Pretexting & Social Engineering Frameworks

Pull this skill when planning a social engineering assessment (vishing, SMiShing, physical tailgating, or in-person pretexts) and need a framework for developing credible pretexts and managing operational security.

> **⚠️ ROE REQUIRED**: Social engineering testing MUST be explicitly authorized in the Rules of Engagement. This includes any form of pretexting, impersonation, or deception of target personnel.

## Pretext development framework

A pretext is a fabricated scenario used to engage a target. Every credible pretext needs these five elements:

### 1. Cover identity
```
Name:             [Realistic name matching the target's culture/region]
Role:             [IT Support / Vendor / Auditor / Facilities / New Hire]
Organization:     [Real company or plausible fictional one]
Contact method:   [Phone / Email / SMS / In-person]
Backstory:        [2-3 sentences explaining WHY you're contacting them]
```

### 2. Research requirements
```bash
# Before any contact, gather:
#   Target's name and title
#   Reporting structure (who is their manager)
#   Current projects or events (conference, audit, office move)
#   Company terminology (internal tool names, acronyms)
#   Physical location (building, floor, parking)

# Use OSINT:
# LinkedIn — job titles, reporting structure, skills
# Company website — news, events, org chart
# GitHub — internal tool names, email patterns
# Shodan — VPN portals, remote access pages
```

### 3. The hook
```
Emotion to trigger:   Urgency / Authority / Curiosity / Social proof / Reciprocity
Urgency angle:        "Security incident on your account" / "Failed login attempts"
Authority angle:      "Your manager asked me to contact you about..."
Helpfulness angle:    "I'm from IT — we're updating the VPN certificate"
```

### 4. The ask
```
What you need:        Password reset / MFA code / Door access / Badge cloning
Method:               "Can you read me the code on your screen?"
Escalation path:      "If you can't, I'll need to escalate to your director"
```

### 5. Escape plan
```
If challenged:        "I'll have my manager reach out to your manager to sort this out"
If detected:          "Let me check with my supervisor and get back to you"
Trigger withdrawal:   Pre-arranged signal to abort the engagement
```

## Vishing (voice phishing) framework

### Vishing call script template
```
OPERATOR:     Hello, this is [name] from [org]. Am I speaking with [target]?
TARGET:      Yes...
OPERATOR:    Great. I'm calling about [pretext — e.g., unusual login attempt].
             I need to verify your identity. Can you confirm your [email/username]?
TARGET:      [provides info]
OPERATOR:    Thank you. I'm sending a verification code to your phone.
             Can you read me the code once you receive it?
TARGET:      [reads MFA code / password / other sensitive info]
OPERATOR:    Thanks, that verifies your account. We'll send a follow-up email
             with details. Have a good day.
```

### Call setup
```bash
# Use a spoofed caller ID (where legal under ROE):
#   Twilio — programmable voice API
#   SpoofCard — simple spoofing service
#   VoIP provider with outbound CLI override

# Set up call recording:
#   Twilio: record=true in voice webhook
#   Local: use a VoIP softphone with recording (Zoiper, Linphone)

# Voice modulation (if needed to disguise identity):
#   Use remove background noise for clarity (not distortion)
#   Slight pitch shift if the target knows you
```

## SMiShing (SMS phishing)

### SMS template examples
```
[URGENT] Your package from Amazon is on hold due to failed delivery.
Update your address here: https://amzn-update-xyz.com/pg

[SECURITY ALERT] Unusual sign-in detected on your account.
Verify immediately: https://security-verify-xyz.com

[IT HELP DESK] Your password expires in 24 hours.
Renew here: https://company-portal-xyz.com
```

### SMS delivery
```bash
# Use burner SIM + GSM modem for small-scale (10-100 messages)
# Use SMS gateway API (Twilio, AWS SNS) for large-scale

# SMS gateway via Twilio:
curl -X POST https://api.twilio.com/2010-04-01/Accounts/ACxxx/Messages.json \
  --data-urlencode "Body=Your package is on hold. Update here: https://..." \
  --data-urlencode "From=+15551234567" \
  --data-urlencode "To=+15559876543" \
  -u ACxxx:AuthToken
```

## Physical social engineering

### Tailgating / Piggybacking
```
Approach:             Approach a secure door with hands full (box, coffee)
Pretext:              "I forgot my badge — can you grab the door?"
Alternative:          "I'm from the AC company, here to service unit 42"

Smoking area:         Wait near the smoking area, make small talk, follow in
Delivery entrance:    "I have a delivery for [employee on floor 3]"
```

### Office walk-through pretexts
```
IT Audit:             "I need to verify asset tags on floor 2"
Fire Safety:          "Annual inspection — need to check extinguishers"
Cleaning:             "New cleaning crew — floor 3 restrooms"
Visitor:              "Here for the 2pm interview with HR"
```

## Operational security

| Principle | Implementation |
|-----------|---------------|
| Burner identity | Never use your real name, number, or email |
| Separate infrastructure | Use different VPS, phone, and email for each campaign |
| Timeboxed engagement | Maximum 1 week per pretext before rotation |
| No permanent records | Wipe all call logs, SMS records, and portal data after campaign |
| Escalation plan | Pre-arranged lawyer contact and reporting procedure |
| Trigger word | Agreed phrase to immediately abort ("The vendor sent the wrong model") |

## Validation shape

A social engineering finding should include:
- **Type**: Vishing / SMiShing / Physical / Phishing (see phishing_kit skill)
- **Targets**: Role and count of targeted individuals (anonymized)
- **Pretext**: Description of the scenario used
- **Success rate**: How many fell for it vs. reported it
- **Information gained**: Type of data/access obtained
- **Detection**: If the target reported the attempt to their SOC
- **Training recommendation**: Specific training focus areas

## Legal and ethical boundaries

| Activity | Typical authorization required |
|----------|-------------------------------|
| Phishing emails | Yes — explicit scope |
| Vishing | Yes — explicit scope, may need call recording consent |
| SMiShing | Yes — explicit scope, SMS spoofing may be illegal |
| Physical tailgating | Yes — needs facility management coordination |
| Impersonating law enforcement | NEVER — illegal in all jurisdictions |
| Recording without consent | Check jurisdiction — may require two-party consent |

## Hand-off

- For phishing website setup: `-> /skill/social_engineering/phishing_kit`
- After gathering credentials: `-> /skill/cloud/azure` or `-> /skill/active_directory/ad_kill_chain`
- After physical access: `-> /skill/network/arp_spoofing` (plug into internal port)
- For report writing on SE campaign results: `-> /skill/reporting/finding_writing`

## Pro tips

- **Reciprocity is the strongest trigger**: Doing something for the target first (sending a "thanks for participating in our survey" gift card) makes them 3x more likely to comply with a subsequent request.
- **Authority without aggression**: Using authoritative language ("Security policy requires...") is effective. Being aggressive or rude triggers resistance.
- **Current events are gold**: Use real company events — "I'm calling about the office move next week" or "Regarding the team offsite registration."
- **Know when to abort**: If a target says "I'm reporting this to security," have an immediate graceful exit ("Thank you, you should. I'm sorry to have disturbed you.") and move on. DO NOT escalate.
- **Document everything**: Record calls (with consent where required), save SMS templates, and log timestamps. Social engineering assessments are the most legally sensitive test type.
- **Target selection**: Start with new employees (less security awareness) and managers (more likely to respond to authority). Avoid security team members unless specifically scoped.

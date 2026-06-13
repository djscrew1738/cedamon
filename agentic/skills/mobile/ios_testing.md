---
name: iOS Application Testing
description: iOS security assessment including IPA analysis, runtime manipulation with Frida/objection, insecure storage, and traffic interception
---

# iOS Application Testing

Pull this skill when testing an iOS application (IPA) for security vulnerabilities. iOS testing typically requires a jailbroken device or a developer-signed IPA for dynamic analysis.

## Tool wiring

| Action | Tool | Notes |
|--------|------|-------|
| Static analysis | `kali_shell` — `MobSF` (docker) | IOS IPA analysis via upload |
| Binary analysis | `kali_shell` — `otool`, `class-dump`, `nm` | Mach-O binary inspection |
| Runtime analysis | `kali_shell` — `frida`, `objection` | Must be installed on the iOS device |
| Device interaction | `kali_shell` — `usbmuxd`, `iproxy` | USB connection to iOS device |
| Traffic interception | `kali_shell` — `mitmproxy`, `burpsuite` | Proxy through your machine |
| Keychain inspection | `kali_shell` — `frida` / `objection` | Dump iOS keychain contents |
| Plist inspection | `kali_shell` — `plutil` | Convert/read plist files |

> **Availability**: usbmuxd, libimobiledevice, and plutil may need `apt install`. Frida server must be installed on the iOS device.

## Primer

iOS app testing has unique constraints vs Android:
- **App Sandbox**: Each app runs in its own sandbox — iOS is significantly more restrictive
- **Code Signing**: All apps must be signed; runtime code signing verification
- **Jailbreak Required**: Full dynamic analysis (Frida, Cycript) needs a jailbroken device
- **IPA Access**: You need the IPA file (App Store encrypted IPA, or developer-signed build)
- **Keychain**: iOS keychain is hardware-backed and app-specific

## Setup

### Extract IPA from a device
```bash
# With a jailbroken device via Frida:
frida-ps -U -a  # List running apps
frida-discover -U -f com.target.app

# Dump IPA from installed app (jailbroken):
objection -g com.target.app explore
# ios bundle dump_binary
```

### Install and run Frida on iOS
```bash
# On jailbroken device (via Cydia or Sileo):
# Install frida from https://build.frida.re

# Verify connection:
frida-ls-devices
frida-ps -U

# On non-jailbroken device:
# Need app compiled with Frida Gadget injected, or sideload with developer cert
```

### Traffic interception
```bash
# Start mitmproxy on your machine:
mitmproxy -p 8080 --mode transparent

# Connect iOS device proxy:
# Settings > Wi-Fi > Configure Proxy > Manual
# Set server to your machine's IP, port 8080

# Install mitmproxy CA:
# Safari > http://mitm.it > Download iOS certificate
# Settings > General > Profiles > Install
# Settings > General > About > Certificate Trust Settings > Enable

# For all traffic via USB (no Wi-Fi needed):
iproxy 8080 8080 &
# Then set iOS device proxy to 127.0.0.1:8080 via USB tunnel
```

## Static analysis

### Decrypt App Store IPA (jailbroken device)
```bash
# Frida script to decrypt App Store encrypted IPA:
# frida --codesign -U -f com.target.app -l decrypt.js
# Or use objection:
objection -g com.target.app explore
# ios bundles list_bundles
# ios bundles download_bundle
```

### App binary analysis
```bash
# Check binary protections
otool -arch arm64 -l Payload/Target.app/Target | grep -A 4 LC_ENCRYPTION_INFO
# LC_ENCRYPTION_INFO cryptid=1 means App Store encrypted

# Check architecture
lipo -info Payload/Target.app/Target

# List symbols (debug symbols left in release?)
nm -arch arm64 Payload/Target.app/Target | grep -i "debug\|test\|secret"

# Check for PIE (Position Independent Executable)
otool -arch arm64 -h Payload/Target.app/Target | grep PIE
```

### Plist inspection
```bash
# Convert binary plist to XML for reading
plutil -convert xml1 Info.plist -o Info.xml

# Check Info.plist for:
#   NSAppTransportSecurity (ATS exceptions — allow HTTP)
#   NSFaceIDUsageDescription (FaceID usage)
#   CFBundleURLTypes (scheme handlers)
#   UIBackgroundModes (background execution)
```

### MobSF analysis
```bash
# Upload IPA to MobSF (same as Android)
# MobSF provides automated analysis of:
#   - Binary protections (PIE, ARC, stack canary)
#   - Insecure API usage (NSUserDefaults, UIWebView)
#   - Hardcoded secrets in binary strings
#   - Permission analysis
```

## Dynamic analysis

### Bypass certificate pinning
```bash
# Using objection:
objection -g com.target.app explore
# ios sslpinning disable

# Or using a Frida script:
frida -U -f com.target.app -l ssl_bypass_ios.js
```

### Dump keychain data
```bash
# With objection:
objection -g com.target.app explore
# ios keychain dump

# With Frida:
frida -U com.target.app -l dump_keychain.js
```

### Inspect view hierarchy
```bash
# Find which view/VC is on screen:
frida -U com.target.app -e "ObjC.classes.UIViewController._verboseLog()"
```

### Bypass jailbreak detection
```bash
# Using objection:
objection -g com.target.app explore
# ios jailbreak disable

# Or Frida script:
# var JB = ObjC.classes.JailbreakDetection;
# JB.isJailbroken.implementation = function() { return 0; };
```

## iOS-specific vulnerability checks

### Insecure data storage

```bash
# NSUserDefaults
objection -g com.target.app explore
# ios nsuserdefaults get

# CoreData / SQLite (app sandbox)
# objection can explore the filesystem:
# ls /var/mobile/Containers/Data/Application/<app-uuid>/Library/
```

### WebView vulnerabilities
```bash
# Check for UIWebView (deprecated — no JavaScript injection protection)
# Or WKWebView with JavaScriptEnabled

# Test XSS in WebView:
# Look for any URL schemes or JavaScript bridges exposed to WebView content
```

### URL scheme hijacking
```bash
# From Info.plist identified schemes:
# targetapp://transfer?amount=100&to=attacker

# Test for CSRF via URL schemes:
# <img src="targetapp://transfer?amount=10000&to=attacker">

# Test for arbitrary parameter injection
```

### Insecure deep link handling
```bash
# Using a custom tool to send deep links:
# (requires a Mac or iOS device)
# Examples of what to test:
#   targetapp://login?token=leaked_token
#   targetapp://reset-password?email=victim@target.com
```

## Detection avoidance

| Signal | OPSEC note |
|--------|------------|
| Jailbreak detection | Many production apps detect jailbreak. Use Frida/objection to bypass |
| Frida detection | Some apps scan for Frida's D-Bus. Use Frida Gadget (injected into IPA) |
| Proxy detection | Use `iproxy` USB tunnel instead of Wi-Fi proxy (harder to detect) |
| Certificate trust | Apps may use `AFNetworking` SSL pinning that checks against embedded certs |
| App sandbox | You cannot access other apps' data without a sandbox escape (rare on iOS) |

## Validation shape

An iOS finding should include:
- **App**: Bundle identifier, version, build number
- **Device**: iOS version, device model
- **Jailbreak status**: Whether a jailbreak was required for discovery
- **Vulnerability type**: Insecure storage, ATS bypass, URL scheme hijacking, etc.
- **PoC**: Steps to reproduce (commands, Frida scripts, HTTP requests)
- **Data exposed**: Type and sensitivity of data

## Common pitfalls

| Pitfall | Fix |
|---------|-----|
| App Store IPA is encrypted | You must decrypt it first (requires jailbroken device) for binary analysis |
| No jailbroken device available | Use MobSF for static analysis only; dynamic testing needs a device |
| ATS blocking HTTP | App Transport Security blocks all HTTP by default. Only testable if ATS exceptions exist |
| Code signing prevents modifications | Frida Gadget injection requires re-signing the IPA. Use `ios-deploy` with developer cert |
| Frida connection lost on app crash | Use `frida -f` (spawn) instead of `frida -n` (attach) for crash-prone targets |

## False positives

- **NSUserDefaults storing non-sensitive data**: Not all NSUserDefaults values are security-relevant. Review if the stored data (e.g., UI state, preferences) contains session tokens or PII.
- **ATS exceptions for known CDNs**: Some apps have ATS exceptions for specific CDNs (e.g., `*.cloudfront.net`). Evaluate whether the exception allows HTTP or just widens TLS requirements.
- **URL scheme exposed without validation**: Not all URL scheme handlers perform sensitive actions. Test each handler individually.

## Hand-off

- After finding network endpoints: `-> /skill/api_security/openapi_swagger_exposure`
- For cloud backend: `-> /skill/cloud/aws` or `-> /skill/technologies/firebase_firestore`
- For backend API fuzzing: `-> /skill/tooling/ffuf`
- For Android equivalent: `-> /skill/mobile/android_testing`

## Pro tips

- **No jailbreak? Use a Simulator**: Xcode's iOS Simulator (macOS only) allows runtime analysis with objection and Frida since it runs without code signing enforcement. Limited to x86_64 architecture but most apps run fine.
- **Data Protection Classes**: iOS encrypts files at rest based on protection class (`NSFileProtectionComplete`, etc.). Check which class is used — `NSFileProtectionNone` means files are accessible anytime, even when the device is locked.
- **KTRW (Kernel Trust Rootkit Walker)**: For advanced iOS testing, a bootrom exploit (checkm8) allows kernel-level debugging on A5-A11 devices. Use this for testing sandbox escapes.
- **Frida Gadget for non-jailbroken**: Inject `FridaGadget.dylib` into the IPA, re-sign with a developer certificate, and deploy with `ios-deploy`. This gives you full Frida capabilities on a non-jailbroken device.
- **Snapshots in app switcher**: iOS automatically takes a screenshot when the app backgrounds. Check if the app blurs sensitive data (e.g., banking transactions) in `applicationDidEnterBackground`.

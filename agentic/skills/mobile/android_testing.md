---
name: Android Application Testing
description: Android security assessment including static analysis, dynamic instrumentation, insecure storage, and API interception with MobSF, Frida, and ADB
---

# Android Application Testing

Pull this skill when testing an Android application (APK/AAB) for security vulnerabilities including insecure data storage, insecure communication, authentication flaws, and client-side injection.

## Tool wiring

| Action | Tool | Notes |
|--------|------|-------|
| Static analysis | `kali_shell` — `MobSF` (docker) | Comprehensive APK analysis |
| Dynamic instrumentation | `kali_shell` — `frida`, `objection` | Runtime manipulation |
| APK manipulation | `kali_shell` — `apktool`, `jadx`, `dex2jar` | Decompile, repackage, sign |
| Device interaction | `kali_shell` — `adb` (Android Debug Bridge) | Connect to emulator/device |
| Traffic interception | `kali_shell` — `mitmproxy`, `burpsuite` | Proxy HTTP/HTTPS through your machine |
| Intent fuzzing | `kali_shell` — `adb shell am` | Send malformed intents to activities/services |
| Storage inspection | `kali_shell` — `adb shell run-as` | Read app's private data directory |

> **Availability**: ADB pre-installed. MobSF, apktool, jadx, frida may need `apt install` or docker pull.

## Primer

Android app testing typically involves three layers:
1. **Static analysis** — decompile the APK and review code, resources, and manifest
2. **Dynamic analysis** — run the app and intercept/modify its behaviour at runtime
3. **Network analysis** — inspect API calls between the app and backend

## Setup

### Start ADB and connect a device/emulator
```bash
# List connected devices
adb devices

# If using an emulator (Android Studio AVD or Genymotion)
# Ensure USB debugging is enabled on physical devices

# Install the target APK
adb install target-app.apk

# Verify installation
adb shell pm list packages | grep target
```

### Set up traffic interception
```bash
# Install mitmproxy CA cert on the device (for HTTPS inspection)
adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /sdcard/
adb shell 'mv /sdcard/mitmproxy-ca-cert.pem /sdcard/Download/'
# On device: Settings > Security > Install from storage

# Or with a rooted device:
adb remount
adb push ~/.mitmproxy/mitmproxy-ca-cert.pem /system/etc/security/cacerts/
```

### Proxy the device through your machine
```bash
# On your machine, start mitmproxy:
mitmproxy -p 8080 --mode transparent

# On the device, set proxy:
adb shell settings put global http_proxy your-ip:8080

# Or use iptables on a rooted device to redirect all traffic:
adb shell iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port 8080
adb shell iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-port 8080
```

## Static analysis with MobSF

```bash
# Start MobSF (Docker)
docker run -it -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest

# Upload APK via web UI at http://localhost:8000
# MobSF will analyze and provide:
#   - Code analysis (hardcoded secrets, insecure APIs)
#   - Manifest analysis (exported components, permissions)
#   - Binary analysis (native libraries, obfuscation)
#   - Malware analysis (known bad signatures)
```

### Key manifest checks
```bash
# Extract and examine AndroidManifest.xml
apktool d target-app.apk -o /tmp/app-decompiled
cat /tmp/app-decompiled/AndroidManifest.xml

# Flag these:
#   android:allowBackup="true"  — app data can be backed up via ADB
#   android:debuggable="true"   — debug mode enabled in production
#   android:exported="true" on activities/services — accessible from other apps
#   android:usesCleartextTraffic="true" — allows HTTP (non-HTTPS) traffic
```

### Hardcoded secrets
```bash
# Search for common secret patterns in decompiled code
jadx -d /tmp/app-source target-app.apk
grep -r "api_key\|apiKey\|API_KEY\|secret\|password\|token" /tmp/app-source/ \
  --include="*.java" --include="*.xml" -l
```

## Dynamic analysis with Frida

### Bypass SSL pinning
```bash
# Frida script to bypass common SSL pinning implementations
frida -U -f com.target.app --no-pause -l ssl_bypass.js

# Or use objection's built-in bypass:
objection -g com.target.app explore
# android sslpinning disable
```

### Dump runtime data
```bash
# Dump all classes and their methods
frida -U com.target.app -e "Java.perform(function() { Java.enumerateLoadedClasses({onMatch: function(c) {console.log(c)}, onComplete: function() {}}); })"

# Dump all SharedPreferences
adb shell run-as com.target.app cat /data/data/com.target.app/shared_prefs/*.xml

# Dump SQLite databases
adb shell run-as com.target.app sqlite3 /data/data/com.target.app/databases/app.db ".dump"
```

### Intercept method calls
```bash
# Frida script to intercept a specific method:
# Java.perform(function() {
#   var cls = Java.use('com.target.app.network.ApiClient');
#   cls.signRequest.implementation = function(req) {
#     console.log('signRequest called with:', req);
#     return this.signRequest(req);
#   };
# });

# Run with:
frida -U -l intercept.js com.target.app
```

## Insecure data storage checks

```bash
# Check app's private directory
adb shell run-as com.target.app ls -la /data/data/com.target.app/
adb shell run-as com.target.app cat /data/data/com.target.app/databases/*.db
adb shell run-as com.target.app ls -la /data/data/com.target.app/shared_prefs/

# Check external storage
adb shell ls -la /sdcard/Android/data/com.target.app/

# Check for logs containing sensitive data
adb logcat -d | grep -i "password\|token\|secret\|credit"

# Check for WebView caching
adb shell run-as com.target.app cat /data/data/com.target.app/app_webview/*.db
```

## Intent fuzzing (exported components)

```bash
# List all exported activities
adb shell pm dump com.target.app | grep -A 5 "Activity" | grep "exported=true"

# Start an exported activity with crafted extras
adb shell am start -n com.target.app/.activities.SettingsActivity \
  --ei admin_mode 1 \
  --es auth_token "test"

# Send malformed intents to exported receivers
adb shell am broadcast -a com.target.app.ACTION_PROCESS \
  --es data "$(python3 -c 'print("A"*10000)')"
```

## Deep link testing

```bash
# Extract deep link schemes from manifest
grep -r "android:scheme\|android:host\|android:path" /tmp/app-decompiled/AndroidManifest.xml

# Test deep link injection
adb shell am start -d "targetapp://settings?user_id=admin&role=admin"
adb shell am start -d "targetapp://webview?url=javascript:alert(1)"
adb shell am start -d "targetapp://redirect?url=http://evil.com"
```

## Detection avoidance

| Signal | OPSEC note |
|--------|------------|
| USB debugging enabled | Only during testing; disable for physical devices in the field |
| Frida detection | Some apps detect Frida via D-Bus or port scanning. Use Frida Gadget or rename frida-server |
| Root detection | Use `objection android root disable` or patch the APK to bypass root checks |
| Certificate installation | Some apps detect new CA certs. Use a rooted device with Magisk + TrustMeAlready module |

## Validation shape

An Android finding should include:
- **App**: Package name, version, build number
- **Device/OS**: Android version, device model
- **Vulnerability type**: Insecure storage, SSL pinning bypass, exported component, etc.
- **PoC**: ADB commands, Frida scripts, or manual steps to reproduce
- **Data exposed**: Type and sensitivity of data accessed (PII, tokens, credentials)
- **Impact**: What an attacker with physical device access or a malicious app could achieve

## Common pitfalls

| Pitfall | Fix |
|---------|-----|
| `adb: device unauthorized` | Accept the RSA key prompt on the device |
| App detects Frida and crashes | Use Frida Gadget (repackaged with the APK) or `frida -R` instead of `-U` |
| SSL pinning bypass fails | The app may use certificate transparency (Certificate Pinning v2). Use Frida script for OkHttp/TrustManager hook. |
| MobSF analysis takes too long | Use `--quick` mode or limit to specific checks (manifest, permissions, hardcoded secrets) |
| Emulator has no Google Play Services | Use a real device or Genymotion emulator (includes Google Services) |

## False positives

- **SharedPreferences in XML**: Some apps cache server responses in SharedPreferences to reduce network calls. If the data is not sensitive PII or credentials, this may be intended behaviour.
- **Debuggable flag in manifest**: May be a build artifact (debug build configuration). Verify by checking the app signature — test/debug builds use different signing keys.
- **Exporting activities without permission**: An activity exported but not documented is not automatically a vulnerability. Check if the activity can be used to bypass auth or access privileged functions.

## Hand-off

- After discovering API endpoints: `-> /skill/api_security/openapi_swagger_exposure` and test the backend APIs
- For cloud backend analysis: `-> /skill/cloud/aws` or `-> /skill/cloud/gcp` if the app uses Firebase
- For iOS equivalent: `-> /skill/mobile/ios_testing`

## Pro tips

- **Always check the backup flag first**: `android:allowBackup="true"` with `adb backup` gives you a full app data dump including all databases and shared preferences. This is the easiest win.
- **Frida is your scalpel**: Learn Frida's Java bridge — you can hook any method, change return values, bypass any check, and dump any variable at runtime. Objection is a good wrapper but Frida scripts are more powerful.
- **Burp vs mitmproxy**: Burp Suite has better UI for manual testing; mitmproxy has better scripting (Python) for automated flows. Use Burp for interactive and mitmproxy for automated/replay testing.
- **Check for Firebase**: Many Android apps use Firebase Firestore/Realtime Database. `-> /skill/technologies/firebase_firestore` for Firebase-specific testing.
- **Emulators vs real devices**: Emulators (Android Studio AVD) are faster for static analysis and most dynamic tests. Real devices are needed for hardware-specific features (NFC, Bluetooth, biometrics).

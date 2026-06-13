"""
RedAmon Infrastructure Exposure Analysis Prompts

Discovery of exposed, misconfigured, or unintentionally public infrastructure
belonging to a target domain: open databases, exposed cloud storage,
unauthenticated APIs, shadow IT, and internet-facing management interfaces.

This skill is DISTINCT from:
- attack_surface_mapping (aims for COMPLETE inventory, not just exposed assets)
- cloud_infra_exploitation (requires credentials / control plane access)
- domain_takeover (focuses on DNS control acquisition)
- container_k8s (orchestration layer only)
"""

# =============================================================================
# INFRASTRUCTURE EXPOSURE MAIN WORKFLOW
# =============================================================================

INFRASTRUCTURE_EXPOSURE_TOOLS = """
## ATTACK SKILL: INFRASTRUCTURE EXPOSURE ANALYSIS

**CRITICAL: This attack skill has been CLASSIFIED as Infrastructure Exposure Analysis.**
**You MUST follow the infrastructure exposure workflow below.**

This skill covers FIVE exposure categories:
1. **Exposed cloud storage** — public S3 buckets, GCS buckets, Azure Blob containers,
   open CDN origins, backup archives
2. **Open databases and APIs** — unauthenticated ElasticSearch, MongoDB, Redis,
   GraphQL introspection, REST APIs without auth, Swagger/OpenAPI docs
3. **Management interfaces** — exposed admin panels, database UIs (phpMyAdmin,
   MongoDB Compass), CI/CD dashboards, Kubernetes dashboards, Docker registries
4. **Shadow IT and orphaned assets** — forgotten subdomains pointing to deleted
   resources, old staging/dev environments, unmaintained services
5. **Source code and secret exposure** — Git repositories, .env files,
   backup archives, exposed .git directories, API keys in JS bundles

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
Cloud storage scan enabled:       {iea_storage_enabled}
Database/API exposure enabled:    {iea_db_api_enabled}
Management interface scan enabled:{iea_mgmt_enabled}
Shadow IT discovery enabled:      {iea_shadow_enabled}
Secret exposure scan enabled:     {iea_secrets_enabled}
Shodan integration enabled:       {iea_shodan_enabled}
Google dorking enabled:           {iea_dorking_enabled}
Target domain:                    {iea_target_domain}
IP range hints:                   {iea_ip_ranges}
```

**Hard rules:**
- If `Cloud storage scan enabled: False`, do NOT list bucket contents or
  download files. Only check for bucket existence.
- If `Database/API exposure enabled: False`, do NOT interact with exposed
  databases or APIs beyond a TCP connect / HTTP OPTIONS probe.
- If `Secret exposure scan enabled: False`, do NOT download or inspect
  potentially sensitive files (backups, .env, source code).
- NEVER modify data in exposed databases or storage buckets.
- NEVER access personally identifiable information (PII) in exposed datasets.
- Document every exposed asset with exact URL/IP, exposure type, and
  responsible team hint (from CNAME, headers, or certificate).

---

## MANDATORY INFRASTRUCTURE EXPOSURE WORKFLOW

### Step 1: Asset seeding (query_graph + passive recon)

Pull known assets and enrich with external data:

```cypher
MATCH (d:Domain) WHERE d.name CONTAINS '<target_domain>' RETURN d.name, d.dns_records LIMIT 20
MATCH (s:Subdomain) WHERE s.domain CONTAINS '<target_domain>' RETURN s.name LIMIT 200
MATCH (h:Host) WHERE h.hostname CONTAINS '<target_domain>' RETURN h.ip, h.hostname, h.ports LIMIT 100
MATCH (t:Technology) WHERE t.host CONTAINS '<target_domain>' RETURN t.name, t.version, t.host LIMIT 50
```

Passive enrichment:

```
# Shodan host search for the domain
shodan({{"action": "search", "query": "hostname:<TARGET_DOMAIN>"}})
# Google dorks for exposed files
google_dork({{"query": "site:<TARGET_DOMAIN> filetype:sql OR filetype:bak OR filetype:zip OR filetype:env"}})
google_dork({{"query": "site:<TARGET_DOMAIN> intitle:index.of \"parent directory\""}})
```

**After Step 1, request `transition_phase` to exploitation before deeper probing.**

### Step 2: Cloud storage exposure (CONDITIONAL on `Cloud storage scan enabled`=True)

Test for public buckets matching the target domain or brand name:

```python
# language: python
import boto3, json

# AWS S3 bucket existence check (no credentials needed for some regions)
for name in ['<TARGET_DOMAIN>', '<TARGET>-backup', '<TARGET>-dev', '<TARGET>-staging', '<TARGET>-assets']:
    try:
        resp = boto3.client('s3', region_name='us-east-1').head_bucket(Bucket=name)
        print('EXISTS:', name)
    except Exception as e:
        print('CHECK:', name, type(e).__name__)
```

Also test bucket policy / ACL via anonymous requests:

```
execute_curl({{"args": "-s 'https://<BUCKET_NAME>.s3.amazonaws.com/'"}})
execute_curl({{"args": "-s 'https://<BUCKET_NAME>.s3.amazonaws.com/?acl'"}})
execute_curl({{"args": "-s 'https://storage.googleapis.com/<BUCKET_NAME>/'"}})
execute_curl({{"args": "-s 'https://<BUCKET_NAME>.blob.core.windows.net/?restype=container&comp=list'"}})
```

List bucket contents if listable:

```
execute_curl({{"args": "-s 'https://<BUCKET_NAME>.s3.amazonaws.com/?list-type=2'"}})
```

### Step 3: Database and API exposure (CONDITIONAL on `Database/API exposure enabled`=True)

Probe common database ports and HTTP management endpoints:

```
# ElasticSearch
execute_curl({{"args": "-s 'http://TARGET:9200/_cluster/health'"}})
execute_curl({{"args": "-s 'http://TARGET:9200/_cat/indices'"}})
# MongoDB (if port 27017 is open)
execute_curl({{"args": "-s 'http://TARGET:27017/'"}})
# Redis (if port 6379 is open)
kali_shell({{"command": "(echo 'INFO'; sleep 1) | nc -w 2 TARGET 6379"}})
# Prometheus
execute_curl({{"args": "-s 'http://TARGET:9090/api/v1/status/targets'"}})
# Grafana
execute_curl({{"args": "-s 'http://TARGET:3000/api/admin/settings'"}})
# Kibana
execute_curl({{"args": "-s 'http://TARGET:5601/api/status'"}})
```

For APIs: check for unauthenticated endpoints and documentation:

```
execute_curl({{"args": "-s 'http://TARGET/api/v1/users'"}})
execute_curl({{"args": "-s 'http://TARGET/swagger.json'"}})
execute_curl({{"args": "-s 'http://TARGET/openapi.json'"}})
execute_curl({{"args": "-s 'http://TARGET/graphql' -X POST -H 'Content-Type: application/json' -d '{{"query":"{{ __schema {{ types {{ name }} }} }}"}}'"}})
```

### Step 4: Management interface discovery (CONDITIONAL on `Management interface scan enabled`=True)

Probe for exposed admin panels and dashboards:

```
# Common admin paths
execute_httpx({{"args": "-u http://TARGET/admin -u http://TARGET/phpmyadmin -u http://TARGET/phpMyAdmin -u http://TARGET/api/admin -u http://TARGET/dashboard -u http://TARGET/metrics -u http://TARGET/actuator -u http://TARGET/debug -sc -title -silent -j"}})
# Jenkins
execute_curl({{"args": "-s 'http://TARGET:8080/api/json?pretty=true'"}})
# Kubernetes dashboard
execute_curl({{"args": "-s 'http://TARGET:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/'"}})
# Docker registry
execute_curl({{"args": "-s 'http://TARGET:5000/v2/_catalog'"}})
# RabbitMQ management
execute_curl({{"args": "-s 'http://TARGET:15672/api/overview'"}})
```

### Step 5: Shadow IT and orphaned assets (CONDITIONAL on `Shadow IT discovery enabled`=True)

Find forgotten subdomains and old environments:

```
# Historical DNS data (passive)
web_search({{"query": "<TARGET_DOMAIN> subdomains historical dns", "include_sources": ["tool_docs"]}})
# Certificate transparency for old subdomains
execute_curl({{"args": "-s 'https://crt.sh/?q=%.<TARGET_DOMAIN>&output=json'"}})
# Check if dev/staging/test subdomains still resolve
kali_shell({{"command": "for sub in dev staging test uat qa old beta legacy; do host $sub.<TARGET_DOMAIN>; done"}})
# Wayback Machine for old endpoints
execute_curl({{"args": "-s 'http://web.archive.org/cdx/search/cdx?url=<TARGET_DOMAIN>/*&output=json&collapse=urlkey'"}})
```

### Step 6: Secret and source code exposure (CONDITIONAL on `Secret exposure scan enabled`=True)

Hunt for exposed secrets and source code:

```
# Exposed .git directory
execute_curl({{"args": "-s 'http://TARGET/.git/HEAD'"}})
execute_curl({{"args": "-s 'http://TARGET/.git/config'"}})
# Exposed .env files
execute_curl({{"args": "-s 'http://TARGET/.env'"}})
execute_curl({{"args": "-s 'http://TARGET/.env.production'"}})
# Backup files
execute_curl({{"args": "-s 'http://TARGET/backup.sql'"}})
execute_curl({{"args": "-s 'http://TARGET/database.sql'"}})
execute_curl({{"args": "-s 'http://TARGET/dump.sql'"}})
# Source maps
execute_curl({{"args": "-s 'http://TARGET/static/js/app.js.map'"}})
# JS secrets
execute_jsluice({{"args": "secrets --resolve-paths http://TARGET /tmp/app.js"}})
# gitleaks on any discovered repo
kali_shell({{"command": "gitleaks detect -s /tmp/discovered_repo --report-format json --report-path /tmp/gitleaks.json"}})
```

### Step 7: Reporting requirements

The final report MUST contain:
- **Exposed cloud storage** (bucket names, provider, listability, sensitive files found)
- **Open databases/APIs** (type, URL/IP, port, data volume, authentication status)
- **Management interfaces** (URL, product, version, authentication status)
- **Shadow IT assets** (subdomain, CNAME, age, responsible team hint)
- **Secret exposures** (file path, secret type, count, severity)
- **IP/ASN correlation** (which exposed assets belong to target vs third-party)
- **Remediation** (remove public access, add auth, network segmentation,
  asset inventory automation, secret rotation)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | Exposed asset discovered (bucket, DB, admin panel) | POTENTIAL |
| 2 | Asset confirmed accessible without authentication | POTENTIAL (med) |
| 3 | Sensitive data or secrets extracted from exposed asset | EXPLOITED |
| 4 | Write access to storage/database, or admin panel compromised | EXPLOITED (CRITICAL) |

Only report Level 3+ as exploited. For Level 1-2, document the exact exposure
and access method.
"""


# =============================================================================
# INFRASTRUCTURE EXPOSURE PAYLOAD REFERENCE
# =============================================================================

INFRASTRUCTURE_EXPOSURE_PAYLOAD_REFERENCE = """
## Infrastructure Exposure Reference

### Cloud storage public access indicators

| Provider | Public list indicator | Public read indicator |
|----------|----------------------|----------------------|
| AWS S3 | `ListBucketResult` in XML | 200 on object GET |
| GCS | `ListBucket` in XML | 200 on object GET |
| Azure Blob | `EnumerationResults` in XML | 200 on object GET |
| DigitalOcean Spaces | `ListBucketResult` in XML | 200 on object GET |
| Wasabi | `ListBucketResult` in XML | 200 on object GET |

### Common exposed database ports and endpoints

| Service | Port | Endpoint | Auth check |
|---------|------|----------|------------|
| ElasticSearch | 9200 | `/_cluster/health` | No auth = public |
| MongoDB | 27017 | `/` | No auth = public |
| Redis | 6379 | `INFO` command | No auth = public |
| Memcached | 11211 | `stats` command | No auth = public |
| Cassandra | 9042 | CQLSH | No auth = public |
| CouchDB | 5984 | `/_all_dbs` | No auth = public |
| InfluxDB | 8086 | `/query?q=SHOW DATABASES` | No auth = public |
| Prometheus | 9090 | `/api/v1/status/targets` | Often public |
| Grafana | 3000 | `/api/admin/settings` | Check for anon access |
| Kibana | 5601 | `/app/kibana` | Check for auth |

### Management interface paths

```
/admin
/administrator
/phpmyadmin
/phpMyAdmin
/api/admin
/dashboard
/metrics
/actuator
/actuator/env
/actuator/health
/debug
/console
/jenkins
/swagger-ui.html
/api-docs
/graphiql
/portal
/manage
/server-status
/cpanel
/webmin
```

### Shadow IT subdomain prefixes

```
dev, development, dev1, dev2
test, testing, qa, uat
staging, stage, stg
beta, alpha, preview
legacy, old, archive, backup
api-dev, api-staging, api-test
admin-dev, admin-staging
mail, mx, smtp, pop, imap
ftp, sftp, ssh, vpn, remote
```

### Secret exposure file checklist

```
/.git/HEAD
/.git/config
/.env
/.env.local
/.env.production
/.env.development
/config.php.bak
/wp-config.php.bak
/settings.py.bak
/backup.sql
/dump.sql
/database.sql
/db.zip
/backup.zip
/*.tar.gz
/*.zip
/static/js/*.map
/source.zip
```

### Exposed .git directory exploitation

If `/.git/HEAD` returns a valid git ref:

```bash
# Download the entire .git directory
wget --mirror -I .git http://TARGET/.git/
# Restore the working tree
cd TARGET/.git && git checkout -- .
```

This recovers the full source code repository, including commit history and
potentially hardcoded secrets.
"""

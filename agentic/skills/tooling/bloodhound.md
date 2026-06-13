---
name: BloodHound
description: Active Directory privilege path analysis using BloodHound CE (Enterprise) or BloodHound legacy with SharpHound collectors for attack path mapping
---

# BloodHound

Pull this skill when you have initial AD credentials (regular domain user) and need to map privilege escalation paths to Domain Admin. BloodHound collects data about AD relationships — users, groups, computers, sessions, ACLs — and finds the fastest path to privilege escalation.

## RedAmon wiring

| Action | Tool | Notes |
|--------|------|-------|
| Collect AD data | `kali_shell` — `bloodhound-python` | Python collector for Linux |
| Collect AD data (Windows) | Deploy SharpHound.exe | Better coverage than bloodhound-python |
| Upload to BloodHound CE | Web UI or REST API | Import collected JSON zip |
| Query attack paths | Web UI | Cypher queries or pre-built analytics |
| Analyse with Cypher | Web UI console | Custom graph queries |
| Parse from collection | `kali_shell` — `bloodhound-python -c` | Collection methods |

## Primer

BloodHound works in three phases:

```
1. COLLECT  →  bloodhound-python / SharpHound.exe
        ↓
2. INGEST   →  BloodHound CE (web UI at localhost:8080)
        ↓
3. ANALYSE  →  Built-in queries / custom Cypher → Attack paths
```

**Key concept**: BloodHound maps *relationships*, not just *objects*. It answers questions like:
- "Which users can RDP into which servers?"
- "Which groups have admin access to the domain?"
- "What's the shortest path from my current user to Domain Admin?"

## Collection with bloodhound-python

```bash
# Basic collection (users, groups, computers, trusts)
bloodhound-python -d target.local -u user -p Password123 -dc dc.target.local -c All

# Collection with specific methods
bloodhound-python -d target.local -u user -p Password123 \
  -dc dc.target.local -c Session,Trusts,ACL,Group,LocalAdmin,RDP,DCOM,PSRemote

# Use LDAPS for encrypted channel
bloodhound-python -d target.local -u user -p Password123 \
  -dc dc.target.local --ldaps -c All

# With Kerberos ticket
export KRB5CCNAME=user.ccache
bloodhound-python -d target.local -u user -k -dc dc.target.local -c All

# Output directory
bloodhound-python -d target.local -u user -p Password123 \
  -dc dc.target.local -c All --output-dir ./bloodhound_data
```

### Collection methods

| Method | What it collects | Noise | Notes |
|--------|------------------|-------|-------|
| `Group` | Group membership | Low | LDAP query, barely logged |
| `Session` | Active sessions on machines | Medium | Requires admin on each machine |
| `ACL` | ACEs and permission inheritance | Low | LDAP, might be large output |
| `LocalAdmin` | Local admin groups on machines | High | Requires admin per machine |
| `RDP` | Remote Desktop Users | Medium | Requires admin per machine |
| `DCOM` | DCOM users | Medium | Requires admin per machine |
| `PSRemote` | PowerShell Remoting users | Medium | Requires admin per machine |
| `Trusts` | Domain/forest trusts | Low | LDAP query |
| `All` | Everything above | High | Longest runtime |

Without any administration rights on target machines, use: `-c Group,ACL,Trusts,Session` (session collection only succeeds if you have admin rights or if it uses NetSessionEnum).

## Collection with SharpHound (preferred for Windows)

If you have a Windows machine or shell in the domain, SharpHound collects much better data (especially sessions):

```powershell
# On Windows target (via psexec/wmiexec):
SharpHound.exe --CollectionMethods All --Domain target.local --OutputDirectory C:\temp\

# Noisy but thorough
SharpHound.exe -c All

# Stealthy (LDAP only)
SharpHound.exe -c Group,ACL,Trusts,LocalGroup
```

## Key Cypher queries

### Find all paths to Domain Admin
```cypher
MATCH (u:User) WHERE u.name =~ '(?i)USERNAME@.*'
MATCH (g:Group) WHERE g.name =~ '(?i)DOMAIN ADMINS@.*'
MATCH p = shortestPath((u)-[r:MemberOf|AdminTo|HasSession|AllExtendedRights|AddMember|ForceChangePassword|GenericAll|GenericWrite|WriteOwner|WriteDacl|AllowedToDelegate|AddAllowedToAct|AllowedToAct|GetChanges|GetChangesAll|ReadLAPSPassword|ReadGMSAPassword|HasSIDHistory|DCSync*1..]->(g))
RETURN p
```

### Find Kerberoastable users
```cypher
MATCH (u:User {hasspn:true}) RETURN u.name, u.samaccountname, u.serviceprincipalname
```

### Find AS-REP roastable users
```cypher
MATCH (u:User {dontreqpreauth:true}) RETURN u.name, u.samaccountname
```

### Find computers with admin sessions for current user
```cypher
MATCH (u:User)-[:HasSession]->(c:Computer) WHERE u.name =~ '(?i)USERNAME@.*'
MATCH p = (u)-[:MemberOf*1..]->(g:Group)<-[:AdminTo]-(c2:Computer)
RETURN DISTINCT c2.name, p
```

### Find constrained delegation
```cypher
MATCH (c:Computer)-[:AllowedToDelegate]->(t:Computer) RETURN c.name, t.name
```

### Find all users with DCSync rights
```cypher
MATCH (u:User) WHERE u.trustedtoauth = true RETURN u.name
-- or --
MATCH (u {domain:'TARGET.LOCAL'}) WHERE u.trustedtoauth = true RETURN u
```

### Find GPO abuse paths
```cypher
MATCH (gpo:GPO)-[:Enforce|ApplyTo*1..]->(c:Computer)
MATCH (u:User)-[:GenericAll|Write|WriteOwner*1..]->(gpo)
RETURN u.name, gpo.name, c.name
```

## Built-in analysis queries (BloodHound CE)

| Query | What it finds |
|-------|---------------|
| Find Shortest Paths to Domain Admins | Most-used — all paths from owned principals to DA |
| Find Shortest Paths to High-Value Targets | Any node marked as high value |
| Find Principals with DCSync Rights | Who can perform DCSync attacks |
| Kerberos Attack Surface | Kerberoastable + AS-REP users |
| Session Collection Overview | Which computers have active user sessions |
| Constrained Delegation Overview | AD delegation abuse paths |
| ACL Attack Surface | All ACE-based privilege paths |
| Find Computers where Users are Local Admin | Direct path from user to computer |

## Interpreting BloodHound results

| Relationship | Meaning | Abuse |
|-------------|---------|-------|
| `MemberOf` | User/group is a member of a group | Group nesting for privilege escalation |
| `AdminTo` | User/group is admin on a computer | Can RDP/WinRM/SMB exec |
| `HasSession` | User has a session on a computer | Can steal token/creds |
| `ForceChangePassword` | Can reset password without knowing current | Change target user's password |
| `GenericAll` | Full control over target | Add to group, reset password, modify |
| `GenericWrite` | Write access to target properties | Write SPN for Kerberoast, write script path |
| `WriteOwner` | Can change owner of target | Take ownership then modify ACL |
| `AddMember` | Can add members to a group | Add your user to Domain Admins |
| `DCSync` | Can replicate directory changes | Dump all domain hashes |
| `AllowedToDelegate` | Constrained/unconstrained delegation | Impersonate users to target service |
| `ReadLAPSPassword` | Can read LAPS admin password | Get local admin on computers |
| `GetChanges/GetChangesAll` | Replication rights | DCSync |

## Pitfalls and recovery

| Pitfall | Fix |
|---------|-----|
| bloodhound-python fails with auth error | Verify credentials work with `ldapsearch` or `smbclient` |
| No session data collected | Need admin rights on machines. Use `-c Group,ACL,Trusts` without session collection |
| BloodHound CE not running | Start it: `docker run -p 8080:8080 -e ... bloodhound` |
| Data too large for UI | Use Neo4j browser (`localhost:7474`) for custom Cypher queries |
| No attack paths found | Your user may genuinely have no privileges. Check for domain trusts or other domains. |
| LAPS passwords not readable | Only shows if `ReadLAPSPassword` ACE exists for collected users |
| "You don't have access to run this collector" | `bloodhound-python` may need specific permissions. Use SharpHound from a Windows host. |

## Hand-off

- After finding attack paths: `-> /skill/active_directory/ad_kill_chain` for execution
- After finding DCSync rights: `-> /skill/tooling/impacket` with `secretsdump.py`
- After finding Kerberoastable users: `-> /skill/tooling/impacket` with `GetUserSPNs.py` then `-> /skill/tooling/hashcat`
- After finding admin access to a computer: `-> /skill/tooling/impacket` with `wmiexec.py`
- For LAPS integration: `-> /skill/tooling/netexec` with `--laps` flag

## Pro tips

- **Start with `-c Group,ACL,Trusts`**: This is LDAP-only, generates no suspicious event logs, and runs in seconds. It reveals most privilege escalation paths without the noise of session collection.
- **Session collection is the real gold**: Most AD compromises start with "User A has a session on Server B where Group C is admin." Session data + ACL data reveals ~80% of attack paths. Without sessions, you only see group membership paths.
- **BloodHound CE vs Legacy**: BloodHound CE (Enterprise) is the modern web-based version. If the legacy Java version is available, it works but lacks some features. Prefer CE: `docker run -p 8080:8080 specterops/bloodhound-ce`.
- **Mark owned nodes**: After compromising a user or computer, mark it as "Owned" in BloodHound. This enables shorter-path queries and shows you what you can reach from your current position.
- **Export for offline use**: BloodHound Neo4j has a REST API. You can export data as JSON for custom analysis: `curl -u neo4j:password "http://localhost:7474/db/data/cypher" -d '{"query":"MATCH (n) RETURN n"}'`.

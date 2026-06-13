import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'

// ---------------------------------------------------------------------------
// Attack Category & Type constants
// ---------------------------------------------------------------------------

export interface AttackSuggestion {
  id: string
  title: string
  description: string
  toolId: string
  category: 'recon' | 'scan' | 'exploit' | 'enrich'
  rationale: string          // why this attack is suggested (shown to user)
  priority: number           // 0=critical, 1=high, 2=medium, 3=low
  graphInputs: Record<string, string>
  prerequisites: string[]    // human-readable list of what's needed
  alreadyRun: boolean        // true if a completed run for this tool exists
  matchedNodeCount: number   // how many graph nodes triggered this suggestion
}

// ---------------------------------------------------------------------------
// Suggestion definitions — each knows how to test its precondition via Cypher
// ---------------------------------------------------------------------------

interface SuggestionDef {
  id: string
  title: string
  description: string
  toolId: string
  category: AttackSuggestion['category']
  priority: number
  /** Cypher that returns `{ count }` — number of matching nodes that justify this attack. */
  cypher: string
  /** Optional: Cypher that returns `{ count }` — number of completed runs for this tool (to avoid re-suggesting). */
  alreadyRunCypher?: string
  makeGraphInputs: (projectId: string) => Record<string, string>
  rationale: string
  prerequisites: string[]
  /** Category key used in alreadyRunCypher for looking up completed runs */
  runToolId?: string
}

const SUGGESTIONS: SuggestionDef[] = [
  {
    id: 'takeover-hunt',
    title: 'Subdomain Takeover Hunt',
    description: 'Check discovered subdomains for cloud service takeover vulnerabilities (AWS S3, Azure, GitHub Pages, etc.)',
    toolId: 'SubdomainTakeover',
    category: 'scan',
    priority: 0,
    cypher: `
      MATCH (n:DomainNode) WHERE n.projectId = $projectId
      WITH n
      MATCH (n)-[:HAS_SUBDOMAIN]->(s:SubdomainNode) WHERE s.projectId = $projectId
      RETURN count(DISTINCT s) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'SubdomainTakeover', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Subdomains were discovered but not yet checked for cloud takeover risks.',
    prerequisites: ['Discovered subdomains', 'DNS resolution data'],
    runToolId: 'SubdomainTakeover',
  },
  {
    id: 'nuclei-scan',
    title: 'Nuclei Vulnerability Scan',
    description: 'Run Nuclei vulnerability scanner against all discovered HTTP endpoints using built-in and custom templates',
    toolId: 'Nuclei',
    category: 'scan',
    priority: 0,
    cypher: `
      MATCH (n:HttpNode) WHERE n.projectId = $projectId AND n.status = 'live'
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'Nuclei', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Live HTTP endpoints were discovered — Nuclei can find CVEs and misconfigurations.',
    prerequisites: ['Live HTTP endpoints', 'Nuclei templates'],
    runToolId: 'Nuclei',
  },
  {
    id: 'nmap-service',
    title: 'Nmap Service Detection',
    description: 'Run Nmap service/version detection on discovered open ports for detailed fingerprinting',
    toolId: 'Nmap',
    category: 'scan',
    priority: 1,
    cypher: `
      MATCH (n:PortNode) WHERE n.projectId = $projectId AND n.state = 'open'
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'Nmap', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Open ports were discovered — Nmap can identify service versions and OS.',
    prerequisites: ['Open ports discovered'],
    runToolId: 'Nmap',
  },
  {
    id: 'js-recon',
    title: 'JS Recon Analysis',
    description: 'Extract endpoints, secrets, API keys, and sensitive paths from discovered JavaScript files',
    toolId: 'JsRecon',
    category: 'enrich',
    priority: 1,
    cypher: `
      MATCH (n:JsFileNode) WHERE n.projectId = $projectId
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'JsRecon', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'JavaScript files were found — JS Recon can extract hidden endpoints and secrets.',
    prerequisites: ['JavaScript files discovered'],
    runToolId: 'JsRecon',
  },
  {
    id: 'jsluice-analysis',
    title: 'Jsluice Secret & Endpoint Extraction',
    description: 'Use Jsluice to extract hardcoded secrets, API keys, and endpoints from JavaScript files',
    toolId: 'Jsluice',
    category: 'enrich',
    priority: 1,
    cypher: `
      MATCH (n:JsFileNode) WHERE n.projectId = $projectId
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'Jsluice', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'JavaScript files are present — Jsluice extracts secrets and API endpoints.',
    prerequisites: ['JavaScript files discovered'],
    runToolId: 'Jsluice',
  },
  {
    id: 'katana-crawl',
    title: 'Endpoint Crawl (Katana)',
    description: 'Crawl live HTTP endpoints to discover hidden paths, endpoints, and parameters',
    toolId: 'Katana',
    category: 'recon',
    priority: 1,
    cypher: `
      MATCH (n:HttpNode) WHERE n.projectId = $projectId AND n.status = 'live'
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'Katana', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Live endpoints exist — crawling discovers hidden API routes and pages.',
    prerequisites: ['Live HTTP endpoints'],
    runToolId: 'Katana',
  },
  {
    id: 'arjun-params',
    title: 'Parameter Discovery (Arjun)',
    description: 'Discover hidden HTTP parameters on live endpoints that could indicate injection points',
    toolId: 'Arjun',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (n:HttpNode) WHERE n.projectId = $projectId AND n.status = 'live'
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'Arjun', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Live endpoints may have undocumented parameters — Arjun finds them via bruteforce.',
    prerequisites: ['Live HTTP endpoints'],
    runToolId: 'Arjun',
  },
  {
    id: 'vhost-discovery',
    title: 'VHost & SNI Enumeration',
    description: 'Discover virtual hosts on target IPs to find hidden applications and admin panels',
    toolId: 'VhostSni',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (n:IpNode) WHERE n.projectId = $projectId
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'VhostSni', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Target IPs are known — VHost discovery can reveal hidden apps and admin panels.',
    prerequisites: ['Target IP addresses'],
    runToolId: 'VhostSni',
  },
  {
    id: 'graphql-scan',
    title: 'GraphQL Security Scan',
    description: 'Test discovered GraphQL endpoints for introspection, query depth, and common vulnerabilities',
    toolId: 'GraphqlScan',
    category: 'scan',
    priority: 1,
    cypher: `
      MATCH (n:HttpNode) WHERE n.projectId = $projectId
      AND (toLower(n.url) CONTAINS 'graphql' OR toLower(n.url) CONTAINS 'gql')
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'GraphqlScan', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'GraphQL endpoints were detected — they may have introspection enabled or be vulnerable.',
    prerequisites: ['GraphQL endpoints detected'],
    runToolId: 'GraphqlScan',
  },
  {
    id: 'shodan-enrich',
    title: 'Shodan Enrichment',
    description: 'Enrich discovered IPs with Shodan intelligence — open ports, services, CVEs, and banners',
    toolId: 'Shodan',
    category: 'enrich',
    priority: 2,
    cypher: `
      MATCH (n:IpNode) WHERE n.projectId = $projectId
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'Shodan', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'IPs are known — Shodan can enrich them with service intelligence and CVEs.',
    prerequisites: ['Target IPs', 'Shodan API key'],
    runToolId: 'Shodan',
  },
  {
    id: 'osint-enrich',
    title: 'OSINT Enrichment Pack',
    description: 'Run all OSINT enrichment tools (Censys, FOFA, OTX, ZoomEye) against discovered targets',
    toolId: 'OsintEnrichment',
    category: 'enrich',
    priority: 3,
    cypher: `
      MATCH (n:DomainNode) WHERE n.projectId = $projectId
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'OsintEnrichment', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'A target domain is known — OSINT enrichment gathers additional intelligence from public sources.',
    prerequisites: ['Target domain', 'API keys (Censys, FOFA, OTX, etc.)'],
    runToolId: 'OsintEnrichment',
  },
  {
    id: 'urlscan-enrich',
    title: 'URLScan.io Enrichment',
    description: 'Look up the target domain on URLScan.io for historical screenshots, DOM snapshots, and related hosts',
    toolId: 'Urlscan',
    category: 'enrich',
    priority: 3,
    cypher: `
      MATCH (n:DomainNode) WHERE n.projectId = $projectId
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'Urlscan', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'URLScan.io can provide historical screenshots and related hosts for the target domain.',
    prerequisites: ['Target domain'],
    runToolId: 'Urlscan',
  },
  {
    id: 'ffuf-fuzz',
    title: 'FFUF Directory Fuzzing',
    description: 'Bruteforce directories and files on live HTTP endpoints to discover hidden resources',
    toolId: 'Ffuf',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (n:HttpNode) WHERE n.projectId = $projectId AND n.status = 'live'
      RETURN count(DISTINCT n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Live endpoints benefit from directory bruteforcing to find hidden resources.',
    prerequisites: ['Live HTTP endpoints', 'Wordlist'],
  },
  {
    id: 'security-checks',
    title: 'Security Headers & Config Checks',
    description: 'Check live endpoints for missing security headers, misconfigurations, and insecure cookies',
    toolId: 'SecurityChecks',
    category: 'scan',
    priority: 2,
    cypher: `
      MATCH (n:HttpNode) WHERE n.projectId = $projectId AND n.status = 'live'
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'SecurityChecks', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Security headers protect users — checking them is quick and finds low-hanging fruit.',
    prerequisites: ['Live HTTP endpoints'],
    runToolId: 'SecurityChecks',
  },
  {
    id: 'ai-surface-recon',
    title: 'AI Surface Recon',
    description: 'Discover AI-related endpoints, LLM configurations, and AI SDK exposure across the attack surface',
    toolId: 'AiSurfaceRecon',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (n:ResourceNode) WHERE n.projectId = $projectId
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'AiSurfaceRecon', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Resources were found — AI surface recon can identify LLM endpoints and AI SDK exposure.',
    prerequisites: ['Discovered web resources'],
    runToolId: 'AiSurfaceRecon',
  },
  {
    id: 'gau-urls',
    title: 'GAU URL History',
    description: 'Fetch known URLs from AlienVault OTX, Wayback Machine, and CommonCrawl for the target domain',
    toolId: 'Gau',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (n:DomainNode) WHERE n.projectId = $projectId
      RETURN count(DISTINCT n) AS count
    `,
    alreadyRunCypher: `
      MATCH (n:PartialReconRun {projectId: $projectId, toolId: 'Gau', status: 'completed'})
      RETURN count(n) AS count
    `,
    makeGraphInputs: (projectId) => ({ projectId }),
    rationale: 'Historical URLs may reveal deprecated endpoints, hidden parameters, and leaked information.',
    prerequisites: ['Target domain'],
    runToolId: 'Gau',
  },
]

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

export async function GET(
  _request: NextRequest,
  { params }: { params: Promise<{ projectId: string }> },
) {
  const { projectId } = await params

  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  try {
    const session = getSession()

    const suggestions: AttackSuggestion[] = []

    for (const def of SUGGESTIONS) {
      try {
        // Check how many matching nodes exist
        const countResult = await session.run(def.cypher, { projectId })
        const count: number = countResult.records[0]?.get('count')?.toNumber() ?? 0

        if (count === 0) continue

        // Check if this tool has already been run successfully
        let alreadyRun = false
        if (def.alreadyRunCypher) {
          const runResult = await session.run(def.alreadyRunCypher, { projectId })
          alreadyRun = (runResult.records[0]?.get('count')?.toNumber() ?? 0) > 0
        }

        suggestions.push({
          id: def.id,
          title: def.title,
          description: def.description,
          toolId: def.toolId,
          category: def.category,
          priority: def.priority,
          rationale: def.rationale,
          graphInputs: def.makeGraphInputs(projectId),
          prerequisites: def.prerequisites,
          alreadyRun,
          matchedNodeCount: count,
        })
      } catch (err) {
        console.error(`[attacks/suggestions] Error checking "${def.id}":`, err)
        // Skip this suggestion on error rather than failing the whole request
      }
    }

    await session.close()

    // Sort: priority (ascending), then matchedNodeCount (descending)
    suggestions.sort((a, b) => {
      const pri = a.priority - b.priority
      if (pri !== 0) return pri
      return b.matchedNodeCount - a.matchedNodeCount
    })

    return NextResponse.json({ suggestions, projectId })
  } catch (err) {
    console.error('[attacks/suggestions] Failed:', err)
    return NextResponse.json(
      { error: 'Failed to generate attack suggestions' },
      { status: 500 },
    )
  }
}

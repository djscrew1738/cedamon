import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/app/api/graph/neo4j'
import prisma from '@/lib/prisma'

function toNum(val: unknown): number {
  if (val && typeof val === 'object') {
    if ('low' in val) return (val as { low: number }).low
    const maybeInt = val as { toNumber?: () => number }
    if (typeof maybeInt.toNumber === 'function') return maybeInt.toNumber()
  }
  return typeof val === 'number' ? val : 0
}

// ---------------------------------------------------------------------------
// Attack Category & Type constants
// ---------------------------------------------------------------------------

export interface AttackSuggestion {
  id: string
  title: string
  description: string
  toolId: string
  category: 'recon' | 'scan' | 'exploit' | 'enrich'
  rationale: string
  priority: number
  graphInputs: Record<string, string>
  prerequisites: string[]
  alreadyRun: boolean
  matchedNodeCount: number
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
  /** Optional: Cypher that returns `{ count }` — number of output nodes that indicate this tool has already run. */
  alreadyRunCypher?: string
  makeGraphInputs: (projectId: string, domain: string) => Record<string, string>
  rationale: string
  prerequisites: string[]
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
      MATCH (s:Subdomain {project_id: $projectId})
      RETURN count(DISTINCT s) AS count
    `,
    alreadyRunCypher: `
      MATCH (v:Vulnerability {project_id: $projectId, source: 'takeover_scan'})
      RETURN count(v) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Subdomains were discovered but not yet checked for cloud takeover risks.',
    prerequisites: ['Discovered subdomains', 'DNS resolution data'],
  },
  {
    id: 'nuclei-scan',
    title: 'Nuclei Vulnerability Scan',
    description: 'Run Nuclei vulnerability scanner against discovered HTTP endpoints using built-in and custom templates',
    toolId: 'Nuclei',
    category: 'scan',
    priority: 0,
    cypher: `
      MATCH (b:BaseURL {project_id: $projectId})
      RETURN count(DISTINCT b) AS count
    `,
    alreadyRunCypher: `
      MATCH (v:Vulnerability {project_id: $projectId, source: 'nuclei'})
      RETURN count(v) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Live HTTP services were discovered — Nuclei can find CVEs and misconfigurations.',
    prerequisites: ['Live HTTP endpoints'],
  },
  {
    id: 'masscan-wide',
    title: 'Masscan Wide Port Scan',
    description: 'Run a high-speed Masscan across discovered IPs to find open ports on common services',
    toolId: 'Masscan',
    category: 'scan',
    priority: 1,
    cypher: `
      MATCH (i:IP {project_id: $projectId})
      RETURN count(DISTINCT i) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Target IPs are known — Masscan can rapidly discover open ports across the network attack surface.',
    prerequisites: ['Target IP addresses'],
  },
  {
    id: 'nmap-service',
    title: 'Nmap Service Detection',
    description: 'Run Nmap service/version detection on discovered open ports for detailed fingerprinting',
    toolId: 'Nmap',
    category: 'scan',
    priority: 1,
    cypher: `
      MATCH (p:Port {project_id: $projectId, state: 'open'})
      RETURN count(DISTINCT p) AS count
    `,
    alreadyRunCypher: `
      MATCH (p:Port {project_id: $projectId, nmap_scanned: true})
      RETURN count(p) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Open ports were discovered — Nmap can identify service versions and OS.',
    prerequisites: ['Open ports discovered'],
  },
  {
    id: 'js-recon',
    title: 'JS Recon Analysis',
    description: 'Extract endpoints, secrets, API keys, and sensitive paths from discovered JavaScript files',
    toolId: 'JsRecon',
    category: 'enrich',
    priority: 1,
    cypher: `
      MATCH (b:BaseURL {project_id: $projectId})
      RETURN count(DISTINCT b) AS count
    `,
    alreadyRunCypher: `
      MATCH (jf:JsReconFinding {project_id: $projectId, finding_type: 'js_file'})
      RETURN count(jf) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Live HTTP services were found — JS Recon can extract hidden endpoints and secrets.',
    prerequisites: ['Live HTTP endpoints'],
  },
  {
    id: 'jsluice-analysis',
    title: 'Jsluice Secret & Endpoint Extraction',
    description: 'Use Jsluice to extract hardcoded secrets, API keys, and endpoints from JavaScript files',
    toolId: 'Jsluice',
    category: 'enrich',
    priority: 1,
    cypher: `
      MATCH (b:BaseURL {project_id: $projectId})
      RETURN count(DISTINCT b) AS count
    `,
    alreadyRunCypher: `
      MATCH (s:Secret {project_id: $projectId, source: 'jsluice'})
      RETURN count(s) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Live HTTP services are present — Jsluice extracts secrets and API endpoints.',
    prerequisites: ['Live HTTP endpoints'],
  },
  {
    id: 'katana-crawl',
    title: 'Endpoint Crawl (Katana)',
    description: 'Crawl live HTTP endpoints to discover hidden paths, endpoints, and parameters',
    toolId: 'Katana',
    category: 'recon',
    priority: 1,
    cypher: `
      MATCH (b:BaseURL {project_id: $projectId})
      RETURN count(DISTINCT b) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Live endpoints exist — crawling discovers hidden API routes and pages.',
    prerequisites: ['Live HTTP endpoints'],
  },
  {
    id: 'arjun-params',
    title: 'Parameter Discovery (Arjun)',
    description: 'Discover hidden HTTP parameters on live endpoints that could indicate injection points',
    toolId: 'Arjun',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (e:Endpoint {project_id: $projectId, is_live: true})
      RETURN count(DISTINCT e) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Live endpoints may have undocumented parameters — Arjun finds them via bruteforce.',
    prerequisites: ['Live HTTP endpoints'],
  },
  {
    id: 'vhost-discovery',
    title: 'VHost & SNI Enumeration',
    description: 'Discover virtual hosts on target IPs to find hidden applications and admin panels',
    toolId: 'VhostSni',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (i:IP {project_id: $projectId})
      RETURN count(DISTINCT i) AS count
    `,
    alreadyRunCypher: `
      MATCH (v:Vulnerability {project_id: $projectId, source: 'vhost_sni_enum'})
      RETURN count(v) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Target IPs are known — VHost discovery can reveal hidden apps and admin panels.',
    prerequisites: ['Target IP addresses'],
  },
  {
    id: 'graphql-scan',
    title: 'GraphQL Security Scan',
    description: 'Test discovered GraphQL endpoints for introspection, query depth, and common vulnerabilities',
    toolId: 'GraphqlScan',
    category: 'scan',
    priority: 1,
    cypher: `
      MATCH (b:BaseURL {project_id: $projectId})
      WHERE toLower(b.url) CONTAINS 'graphql' OR toLower(b.url) CONTAINS 'gql'
      RETURN count(DISTINCT b) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'GraphQL endpoints were detected — they may have introspection enabled or be vulnerable.',
    prerequisites: ['GraphQL endpoints detected'],
  },
  {
    id: 'shodan-enrich',
    title: 'Shodan Enrichment',
    description: 'Enrich discovered IPs with Shodan intelligence — open ports, services, CVEs, and banners',
    toolId: 'Shodan',
    category: 'enrich',
    priority: 2,
    cypher: `
      MATCH (i:IP {project_id: $projectId})
      RETURN count(DISTINCT i) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'IPs are known — Shodan can enrich them with service intelligence and CVEs.',
    prerequisites: ['Target IPs', 'Shodan API key'],
  },
  {
    id: 'osint-enrich',
    title: 'OSINT Enrichment Pack',
    description: 'Run all OSINT enrichment tools (Censys, FOFA, OTX, ZoomEye) against discovered targets',
    toolId: 'OsintEnrichment',
    category: 'enrich',
    priority: 3,
    cypher: `
      MATCH (d:Domain {project_id: $projectId})
      RETURN count(DISTINCT d) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'A target domain is known — OSINT enrichment gathers additional intelligence from public sources.',
    prerequisites: ['Target domain', 'API keys (Censys, FOFA, OTX, etc.)'],
  },
  {
    id: 'urlscan-enrich',
    title: 'URLScan.io Enrichment',
    description: 'Look up the target domain on URLScan.io for historical screenshots, DOM snapshots, and related hosts',
    toolId: 'Urlscan',
    category: 'enrich',
    priority: 3,
    cypher: `
      MATCH (d:Domain {project_id: $projectId})
      RETURN count(DISTINCT d) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'URLScan.io can provide historical screenshots and related hosts for the target domain.',
    prerequisites: ['Target domain'],
  },
  {
    id: 'ffuf-fuzz',
    title: 'FFUF Directory Fuzzing',
    description: 'Bruteforce directories and files on live HTTP endpoints to discover hidden resources',
    toolId: 'Ffuf',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (b:BaseURL {project_id: $projectId})
      RETURN count(DISTINCT b) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
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
      MATCH (b:BaseURL {project_id: $projectId})
      RETURN count(DISTINCT b) AS count
    `,
    alreadyRunCypher: `
      MATCH (v:Vulnerability {project_id: $projectId, source: 'security_check'})
      RETURN count(v) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Security headers protect users — checking them is quick and finds low-hanging fruit.',
    prerequisites: ['Live HTTP endpoints'],
  },
  {
    id: 'ai-surface-recon',
    title: 'AI Surface Recon',
    description: 'Discover AI-related endpoints, LLM configurations, and AI SDK exposure across the attack surface',
    toolId: 'AiSurfaceRecon',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (e:Endpoint {project_id: $projectId, is_ai_framework_detected: true})
      RETURN count(DISTINCT e) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'AI signals were detected — AI surface recon can identify LLM endpoints and AI SDK exposure.',
    prerequisites: ['Discovered web resources with AI signals'],
  },
  {
    id: 'gau-urls',
    title: 'GAU URL History',
    description: 'Fetch known URLs from AlienVault OTX, Wayback Machine, and CommonCrawl for the target domain',
    toolId: 'Gau',
    category: 'recon',
    priority: 2,
    cypher: `
      MATCH (d:Domain {project_id: $projectId})
      RETURN count(DISTINCT d) AS count
    `,
    makeGraphInputs: (projectId, domain) => ({ projectId, domain }),
    rationale: 'Historical URLs may reveal deprecated endpoints, hidden parameters, and leaked information.',
    prerequisites: ['Target domain'],
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

  const project = await prisma.project.findUnique({
    where: { id: projectId },
    select: { targetDomain: true },
  })

  if (!project) {
    return NextResponse.json({ error: 'Project not found' }, { status: 404 })
  }

  const domain = project.targetDomain || ''

  try {
    const session = getSession()

    const suggestions: AttackSuggestion[] = []

    for (const def of SUGGESTIONS) {
      try {
        // Check how many matching nodes exist
        const countResult = await session.run(def.cypher, { projectId })
        const count: number = toNum(countResult.records[0]?.get('count'))

        if (count === 0) continue

        // Check if this tool has already produced output nodes in the graph
        let alreadyRun = false
        if (def.alreadyRunCypher) {
          const runResult = await session.run(def.alreadyRunCypher, { projectId })
          alreadyRun = toNum(runResult.records[0]?.get('count')) > 0
        }

        suggestions.push({
          id: def.id,
          title: def.title,
          description: def.description,
          toolId: def.toolId,
          category: def.category,
          priority: def.priority,
          rationale: def.rationale,
          graphInputs: def.makeGraphInputs(projectId, domain),
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

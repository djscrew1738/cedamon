/**
 * Types for Recon Process Management
 */

export type ReconStatus = 'idle' | 'starting' | 'running' | 'paused' | 'completed' | 'error' | 'stopping'

export interface ReconState {
  project_id: string
  status: ReconStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export interface ReconLogEvent {
  log: string
  timestamp: string
  phase?: string | null
  phaseNumber?: number | null
  isPhaseStart?: boolean
  level: 'info' | 'warning' | 'error' | 'success' | 'action'
  seq?: number
}

export interface ReconSSEEvent {
  event: 'log' | 'error' | 'complete'
  data: ReconLogEvent | { error: string } | { status: string; completedAt?: string; error?: string }
}

export const RECON_PHASES = [
  'Domain Discovery',
  'Port Scanning',
  'HTTP Probing',
  'Resource Enumeration',
  'Vulnerability Scanning',
  'MITRE Enrichment',
] as const

export type ReconPhase = typeof RECON_PHASES[number]

/** Human-friendly descriptions shown during scan progress */
export const PHASE_DESCRIPTIONS: Record<ReconPhase, string> = {
  'Domain Discovery': 'Enumerating subdomains, DNS records, and discovering related assets',
  'Port Scanning': 'Probing common ports to identify running services',
  'HTTP Probing': 'Checking which services respond to HTTP/HTTPS and fingerprinting web servers',
  'Resource Enumeration': 'Crawling and discovering endpoints, APIs, JS files, and hidden paths',
  'Vulnerability Scanning': 'Running Nuclei templates and CVE checks against discovered services',
  'MITRE Enrichment': 'Correlating findings with MITRE ATT&CK framework and threat intelligence',
}

/** Color for each phase (used in logs and progress UI) */
export const PHASE_COLORS: Record<ReconPhase, string> = {
  'Domain Discovery': '#3b82f6',
  'Port Scanning': '#8b5cf6',
  'HTTP Probing': '#06b6d4',
  'Resource Enumeration': '#f59e0b',
  'Vulnerability Scanning': '#ef4444',
  'MITRE Enrichment': '#10b981',
}

// =============================================================================
// GVM Vulnerability Scan Types
// =============================================================================

export type GvmStatus = 'idle' | 'starting' | 'running' | 'paused' | 'completed' | 'error' | 'stopping'

export interface GvmState {
  project_id: string
  status: GvmStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
  /** Vulnerability counts by severity (populated on completion) */
  summary?: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
    total: number
  } | null
}

export const GVM_PHASES = [
  'Loading Recon Data',
  'Connecting to GVM',
  'Scanning IPs',
  'Scanning Hostnames',
] as const

export type GvmPhase = typeof GVM_PHASES[number]

// =============================================================================
// GitHub Secret Hunt Types
// =============================================================================

export type GithubHuntStatus = 'idle' | 'starting' | 'running' | 'paused' | 'completed' | 'error' | 'stopping'

export interface GithubHuntState {
  project_id: string
  status: GithubHuntStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export const GITHUB_HUNT_PHASES = [
  'Loading Settings',
  'Scanning Repositories',
  'Complete',
] as const

export type GithubHuntPhase = typeof GITHUB_HUNT_PHASES[number]

// =============================================================================
// TruffleHog Secret Scan Types
// =============================================================================

export type TrufflehogStatus = 'idle' | 'starting' | 'running' | 'paused' | 'completed' | 'error' | 'stopping'

export interface TrufflehogState {
  project_id: string
  status: TrufflehogStatus
  current_phase: string | null
  phase_number: number | null
  total_phases: number
  started_at: string | null
  completed_at: string | null
  error: string | null
  container_id?: string | null
}

export const TRUFFLEHOG_PHASES = [
  'Loading Settings',
  'Scanning Repositories',
  'Complete',
] as const

export type TrufflehogPhase = typeof TRUFFLEHOG_PHASES[number]

// =============================================================================
// Partial Recon Types
// =============================================================================

export type PartialReconStatus = 'idle' | 'starting' | 'running' | 'paused' | 'completed' | 'error' | 'stopping'

export interface PartialReconState {
  project_id: string
  run_id: string
  tool_id: string
  status: PartialReconStatus
  container_id: string | null
  started_at: string | null
  completed_at: string | null
  error: string | null
  stats: Record<string, number> | null
}

export interface PartialReconListResponse {
  project_id: string
  runs: PartialReconState[]
}

export interface GraphInputs {
  domain: string | null
  existing_subdomains_count: number
  existing_subdomains?: string[]
  existing_ips_count?: number
  existing_ports_count?: number
  existing_baseurls_count?: number
  existing_baseurls?: string[]
  existing_endpoints_count?: number
  existing_graphql_endpoints_count?: number
  existing_ai_endpoints_count?: number
  existing_mcp_endpoints_count?: number
  existing_vector_db_services_count?: number
  existing_external_domains_count?: number
  source: 'graph' | 'settings'
}

export interface UserTargets {
  subdomains: string[]
  ips: string[]
  ip_attach_to: string | null
  ports?: number[]
  urls?: string[]
  url_attach_to?: string | null
}

export interface PartialReconParams {
  tool_id: string
  graph_inputs: Record<string, string>
  user_inputs: string[]
  user_targets?: UserTargets
  include_graph_targets?: boolean
  settings_overrides?: Record<string, unknown>
}

export const PARTIAL_RECON_SUPPORTED_TOOLS = new Set(['SubdomainDiscovery', 'Naabu', 'Masscan', 'Nmap', 'Httpx', 'Katana', 'ZapAjaxSpider', 'Hakrawler', 'Jsluice', 'Gau', 'Kiterunner', 'ParamSpider', 'Arjun', 'Ffuf', 'EndpointAiClassifier', 'AiSurfaceRecon', 'JsRecon', 'GraphqlScan', 'Nuclei', 'SubdomainTakeover', 'BadDns', 'VhostSni', 'SecurityChecks', 'Shodan', 'Urlscan', 'Uncover', 'OsintEnrichment'])

export const PARTIAL_RECON_PHASE_MAP: Record<string, readonly string[]> = {
  SubdomainDiscovery: ['Subdomain Discovery'],
  Naabu: ['Port Scanning'],
  Masscan: ['Port Scanning'],
  Nmap: ['Nmap Service Detection'],
  Httpx: ['HTTP Probing'],
  Katana: ['Resource Enumeration'],
  ZapAjaxSpider: ['Resource Enumeration'],
  Hakrawler: ['Resource Enumeration'],
  Jsluice: ['Resource Enumeration'],
  Gau: ['Resource Enumeration'],
  Kiterunner: ['Resource Enumeration'],
  ParamSpider: ['Resource Enumeration'],
  Arjun: ['Resource Enumeration'],
  Ffuf: ['Resource Enumeration'],
  EndpointAiClassifier: ['Endpoint AI Classification'],
  AiSurfaceRecon: ['AI Surface Recon'],
  JsRecon: ['JS Recon'],
  GraphqlScan: ['Endpoint Discovery', 'Introspection Testing', 'Schema Analysis', 'Vulnerability Detection'],
  Nuclei: ['Vulnerability Scanning'],
  SubdomainTakeover: ['Subdomain Takeover Detection'],
  BadDns: ['BadDNS Takeover Detection'],
  VhostSni: ['VHost & SNI Enumeration'],
  SecurityChecks: ['Security Checks'],
  Shodan: ['Shodan Enrichment'],
  Urlscan: ['URLScan Enrichment'],
  Uncover: ['Uncover Expansion'],
  OsintEnrichment: ['OSINT Enrichment'],
}

// Backward-compatible default (SubdomainDiscovery phases)
export const PARTIAL_RECON_PHASES = PARTIAL_RECON_PHASE_MAP['SubdomainDiscovery']

export type PartialReconPhase = typeof PARTIAL_RECON_PHASES[number]

// =============================================================================
// P3: Scheduling Types
// =============================================================================

export interface ScheduledReconEntry {
  project_id: string
  user_id: string
  pipeline_type: 'full' | 'partial'
  tool_id: string
  scheduled_at: string
  created_at: string
}

export interface ScheduledReconListResponse {
  scheduled: ScheduledReconEntry[]
}

// =============================================================================
// P3: Audit Trail Types
// =============================================================================

export interface ReconAuditEntry {
  run_id: string
  project_id: string
  pipeline_type: 'full' | 'partial' | 'gvm' | 'github_hunt' | 'trufflehog'
  tool_id: string
  status: 'completed' | 'error'
  started_at: string | null
  completed_at: string | null
  duration_seconds: number | null
  phases_completed: number
  total_phases: number
  error: string | null
  user_id: string
}

export interface AuditLogResponse {
  entries: ReconAuditEntry[]
}

// =============================================================================
// P3: Rate Limiting / Queue Types
// =============================================================================

export interface QueuedReconEntry {
  project_id: string
  user_id: string
  pipeline_type: 'full' | 'partial'
  tool_id: string
  queued_at: string
  position: number
}

export interface QueueStatusResponse {
  user_id: string
  active_count: number
  max_concurrent: number
  queued: QueuedReconEntry[]
}

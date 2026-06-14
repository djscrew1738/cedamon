import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup, waitFor } from '@testing-library/react'
import { AttackPanel } from './AttackPanel'
import type { PartialReconState } from '@/lib/recon-types'

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

const mockStartPartialRecon = vi.fn()
const mockStopPartialRecon = vi.fn()
const mockRefetch = vi.fn()
const mockToastInfo = vi.fn()
const mockToastSuccess = vi.fn()
const mockToastError = vi.fn()

const defaultHookReturn = {
  runs: [] as PartialReconState[],
  activeRuns: [] as PartialReconState[],
  isAnyRunning: false,
  isLoading: false,
  error: null as string | null,
  startPartialRecon: mockStartPartialRecon,
  stopPartialRecon: mockStopPartialRecon,
  refetch: mockRefetch,
}

let mutableHookReturn = { ...defaultHookReturn }

vi.mock('@/hooks', () => ({
  useMultiPartialReconStatus: vi.fn(() => mutableHookReturn),
}))

vi.mock('@/components/ui', () => ({
  useToast: () => ({
    info: mockToastInfo,
    success: mockToastSuccess,
    error: mockToastError,
  }),
}))

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const mockSuggestions = [
  {
    id: 'takeover-hunt',
    title: 'Subdomain Takeover Hunt',
    description: 'Check discovered subdomains for cloud service takeover vulnerabilities',
    toolId: 'SubdomainTakeover',
    category: 'scan' as const,
    rationale: 'Subdomains were discovered but not yet checked for cloud takeover risks.',
    priority: 0,
    graphInputs: { projectId: 'p1', domain: 'example.com' },
    prerequisites: ['Discovered subdomains', 'DNS resolution data'],
    alreadyRun: false,
    matchedNodeCount: 12,
  },
  {
    id: 'nuclei-scan',
    title: 'Nuclei Vulnerability Scan',
    description: 'Run Nuclei vulnerability scanner against discovered HTTP endpoints',
    toolId: 'Nuclei',
    category: 'scan' as const,
    rationale: 'Live HTTP services were discovered — Nuclei can find CVEs and misconfigurations.',
    priority: 0,
    graphInputs: { projectId: 'p1', domain: 'example.com' },
    prerequisites: ['Live HTTP endpoints'],
    alreadyRun: false,
    matchedNodeCount: 8,
  },
  {
    id: 'shodan-enrich',
    title: 'Shodan Enrichment',
    description: 'Enrich discovered IPs with Shodan intelligence',
    toolId: 'Shodan',
    category: 'enrich' as const,
    rationale: 'IPs are known — Shodan can enrich them with service intelligence and CVEs.',
    priority: 2,
    graphInputs: { projectId: 'p1', domain: 'example.com' },
    prerequisites: ['Target IPs', 'Shodan API key'],
    alreadyRun: true,
    matchedNodeCount: 3,
  },
]

const mockSurface = {
  services: [{ service: 'http', port: 80, count: 5 }],
  ports: [{ port: 443, protocol: 'tcp', count: 5 }],
  technologies: [{ name: 'nginx', version: '1.18', cveCount: 0 }],
  dnsRecords: [{ type: 'A', count: 10 }],
  securityHeaders: [{ name: 'X-Frame-Options', isSecurity: true, count: 5 }],
  headerCategories: [{ category: 'Security', count: 3 }],
  endpointCategories: [{ category: 'api', count: 4 }],
  endpointTypes: [{ type: 'Static', count: 10 }],
  parameterAnalysis: [{ position: 'query', total: 5, injectable: 1 }],
  cdnDistribution: [{ segment: 'Direct (No CDN)', count: 2 }],
  ipConcentration: [{ ip: '1.2.3.4', subCount: 2, isCdn: false }],
}

function setupFetch() {
  global.fetch = vi.fn(async (url: string | Request | URL) => {
    const urlString = typeof url === 'string' ? url : url.toString()
    if (urlString.includes('/attacks/suggestions')) {
      return {
        ok: true,
        json: async () => ({ suggestions: mockSuggestions, projectId: 'p1' }),
      } as Response
    }
    if (urlString.includes('/attack-surface')) {
      return {
        ok: true,
        json: async () => mockSurface,
      } as Response
    }
    return { ok: false, status: 404, json: async () => ({ error: 'not found' }) } as Response
  })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('AttackPanel', () => {
  beforeEach(() => {
    mutableHookReturn = { ...defaultHookReturn }
    mockStartPartialRecon.mockReset()
    mockStopPartialRecon.mockReset()
    mockRefetch.mockReset()
    mockToastInfo.mockReset()
    mockToastSuccess.mockReset()
    mockToastError.mockReset()
    setupFetch()
  })

  afterEach(() => {
    cleanup()
    vi.restoreAllMocks()
  })

  test('renders attack surface summary and suggestions', async () => {
    render(<AttackPanel projectId="p1" />)

    await waitFor(() => {
      expect(screen.getByText('Attack Surface Overview')).toBeInTheDocument()
    })

    expect(screen.getByText('Subdomain Takeover Hunt')).toBeInTheDocument()
    expect(screen.getByText('Nuclei Vulnerability Scan')).toBeInTheDocument()
    expect(screen.getByText('Shodan Enrichment')).toBeInTheDocument()
  })

  test('filters suggestions by category pills', async () => {
    render(<AttackPanel projectId="p1" />)

    await waitFor(() => expect(screen.getByText('Subdomain Takeover Hunt')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /enrichment/i }))
    expect(screen.getByText('Shodan Enrichment')).toBeInTheDocument()
    expect(screen.queryByText('Subdomain Takeover Hunt')).not.toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /^all$/i }))
    expect(screen.getByText('Subdomain Takeover Hunt')).toBeInTheDocument()
  })

  test('search filters suggestions by title and description', async () => {
    render(<AttackPanel projectId="p1" />)

    await waitFor(() => expect(screen.getByText('Subdomain Takeover Hunt')).toBeInTheDocument())

    const searchInput = screen.getByRole('textbox', { name: /search attack suggestions/i })
    fireEvent.change(searchInput, { target: { value: 'nuclei' } })

    await waitFor(() => {
      expect(screen.getByText('Nuclei Vulnerability Scan')).toBeInTheDocument()
      expect(screen.queryByText('Subdomain Takeover Hunt')).not.toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /clear search/i }))
    expect(screen.getByText('Subdomain Takeover Hunt')).toBeInTheDocument()
  })

  test('starts an attack when Run Attack is clicked', async () => {
    mockStartPartialRecon.mockResolvedValue({
      project_id: 'p1',
      run_id: 'run-001',
      tool_id: 'SubdomainTakeover',
      status: 'starting',
      container_id: 'c1',
      started_at: null,
      completed_at: null,
      error: null,
      stats: null,
    })

    render(<AttackPanel projectId="p1" />)

    await waitFor(() => expect(screen.getByText('Subdomain Takeover Hunt')).toBeInTheDocument())

    const runButtons = screen.getAllByRole('button', { name: /run attack/i })
    fireEvent.click(runButtons[0])

    await waitFor(() => {
      expect(mockStartPartialRecon).toHaveBeenCalledWith({
        tool_id: 'SubdomainTakeover',
        graph_inputs: { projectId: 'p1', domain: 'example.com' },
        user_inputs: [],
        include_graph_targets: true,
      })
    })

    expect(mockToastInfo).toHaveBeenCalledWith('SubdomainTakeover started', 'Subdomain Takeover Hunt')
  })

  test('shows running status badge and stop/logs buttons for active runs', async () => {
    mockStartPartialRecon.mockResolvedValue({
      project_id: 'p1',
      run_id: 'run-002',
      tool_id: 'Nuclei',
      status: 'running',
      container_id: 'c2',
      started_at: null,
      completed_at: null,
      error: null,
      stats: null,
    })

    const onToggleLogs = vi.fn()
    const { rerender } = render(<AttackPanel projectId="p1" onTogglePartialReconLogs={onToggleLogs} />)

    await waitFor(() => expect(screen.getByText('Nuclei Vulnerability Scan')).toBeInTheDocument())

    const runButtons = screen.getAllByRole('button', { name: /run attack/i })
    fireEvent.click(runButtons[1])

    await waitFor(() => {
      expect(mockStartPartialRecon).toHaveBeenCalled()
    })

    mutableHookReturn.runs = [
      {
        project_id: 'p1',
        run_id: 'run-002',
        tool_id: 'Nuclei',
        status: 'running',
        container_id: 'c2',
        started_at: null,
        completed_at: null,
        error: null,
        stats: null,
      },
    ]
    mutableHookReturn.activeRuns = mutableHookReturn.runs
    mutableHookReturn.isAnyRunning = true

    rerender(<AttackPanel projectId="p1" onTogglePartialReconLogs={onToggleLogs} />)

    await waitFor(() => {
      expect(screen.getByText('Running…')).toBeInTheDocument()
    })

    fireEvent.click(screen.getByRole('button', { name: /stop/i }))
    expect(mockStopPartialRecon).toHaveBeenCalledWith('run-002')

    fireEvent.click(screen.getByRole('button', { name: /logs/i }))
    expect(onToggleLogs).toHaveBeenCalledWith('run-002')
  })

  test('shows recent results with stats when a run completes', async () => {
    const { rerender } = render(<AttackPanel projectId="p1" />)

    await waitFor(() => expect(screen.getByText('Attack Surface Overview')).toBeInTheDocument())

    mutableHookReturn.runs = [
      {
        project_id: 'p1',
        run_id: 'run-nuclei-001',
        tool_id: 'Nuclei',
        status: 'completed',
        container_id: 'c1',
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        error: null,
        stats: { vulnerabilities_found: 12, critical: 2 },
      },
    ]

    rerender(<AttackPanel projectId="p1" />)

    await waitFor(() => {
      expect(screen.getByText('Recent Results')).toBeInTheDocument()
    })

    expect(screen.getByText('Nuclei')).toBeInTheDocument()
    expect(screen.getByText(/vulnerabilities found: 12/i)).toBeInTheDocument()
    expect(screen.getByText(/critical: 2/i)).toBeInTheDocument()
  })

  test('offers reverse shell escalation for runs with exploitable findings', async () => {
    const onRequestReverseShell = vi.fn()
    const { rerender } = render(<AttackPanel projectId="p1" onRequestReverseShell={onRequestReverseShell} />)

    await waitFor(() => expect(screen.getByText('Attack Surface Overview')).toBeInTheDocument())

    mutableHookReturn.runs = [
      {
        project_id: 'p1',
        run_id: 'run-nuclei-001',
        tool_id: 'Nuclei',
        status: 'completed',
        container_id: 'c1',
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        error: null,
        stats: { vulnerabilities_found: 5, critical: 1 },
      },
    ]

    rerender(<AttackPanel projectId="p1" onRequestReverseShell={onRequestReverseShell} />)

    await waitFor(() => expect(screen.getByText('Recent Results')).toBeInTheDocument())

    const shellBtn = screen.getByRole('button', { name: /escalate nuclei to reverse shell/i })
    expect(shellBtn).toBeInTheDocument()

    fireEvent.click(shellBtn)
    expect(onRequestReverseShell).toHaveBeenCalledWith(
      expect.objectContaining({ run_id: 'run-nuclei-001', tool_id: 'Nuclei' }),
    )
  })

  test('dismisses a recent result', async () => {
    const { rerender } = render(<AttackPanel projectId="p1" />)

    await waitFor(() => expect(screen.getByText('Attack Surface Overview')).toBeInTheDocument())

    mutableHookReturn.runs = [
      {
        project_id: 'p1',
        run_id: 'run-js-001',
        tool_id: 'JsRecon',
        status: 'completed',
        container_id: 'c1',
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        error: null,
        stats: { secrets_found: 3 },
      },
    ]

    rerender(<AttackPanel projectId="p1" />)

    await waitFor(() => expect(screen.getByText('Recent Results')).toBeInTheDocument())
    expect(screen.getByText('JsRecon')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: /dismiss jsrecon result/i }))

    await waitFor(() => {
      expect(screen.queryByText('JsRecon')).not.toBeInTheDocument()
    })
  })

  test('shows delta badges on summary cards after surface summary changes', async () => {
    render(<AttackPanel projectId="p1" />)

    await waitFor(() => expect(screen.getByText('Attack Surface Overview')).toBeInTheDocument())
    expect(screen.queryByText('+1')).not.toBeInTheDocument()

    // Mutate the mock surface to add a new service, then refresh
    mockSurface.services.push({ service: 'https', port: 443, count: 3 })
    fireEvent.click(screen.getByRole('button', { name: /refresh suggestions/i }))

    await waitFor(() => {
      expect(screen.getByText('+1')).toBeInTheDocument()
    })

    // Clean up mutation
    mockSurface.services.pop()
  })

  test('run all pending starts each pending attack sequentially', async () => {
    mockStartPartialRecon.mockResolvedValueOnce({
      project_id: 'p1',
      run_id: 'run-takeover',
      tool_id: 'SubdomainTakeover',
      status: 'starting',
      container_id: null,
      started_at: null,
      completed_at: null,
      error: null,
      stats: null,
    })
    mockStartPartialRecon.mockResolvedValueOnce({
      project_id: 'p1',
      run_id: 'run-nuclei',
      tool_id: 'Nuclei',
      status: 'starting',
      container_id: null,
      started_at: null,
      completed_at: null,
      error: null,
      stats: null,
    })

    render(<AttackPanel projectId="p1" />)

    await waitFor(() => expect(screen.getByText('Subdomain Takeover Hunt')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /run all pending/i }))

    await waitFor(() => {
      expect(mockStartPartialRecon).toHaveBeenCalledTimes(2)
    })

    expect(mockStartPartialRecon).toHaveBeenNthCalledWith(1, {
      tool_id: 'SubdomainTakeover',
      graph_inputs: { projectId: 'p1', domain: 'example.com' },
      user_inputs: [],
      include_graph_targets: true,
    })
    expect(mockStartPartialRecon).toHaveBeenNthCalledWith(2, {
      tool_id: 'Nuclei',
      graph_inputs: { projectId: 'p1', domain: 'example.com' },
      user_inputs: [],
      include_graph_targets: true,
    })
  })
})

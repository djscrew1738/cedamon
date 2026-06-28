'use client'

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import {
  Target,
  Search,
  Loader2,
  AlertCircle,
  Play,
  Square,
  Bug,
  Package,
  ListChecks,
  RefreshCw,
  Globe,
  Server,
  Cpu,
  FileCode,
  Shield,
  Network,
  X,
} from 'lucide-react'
import styles from './AttackPanel.module.css'
import { useMultiPartialReconStatus } from '@/hooks'
import { useToast } from '@/components/ui'
import type { PartialReconState, PartialReconStatus } from '@/lib/recon-types'
import { AttackSurfaceSummaryCard } from './AttackSurfaceSummaryCard'
import { CategoryFilterBar } from './CategoryFilterBar'
import { AttackResultCard } from './AttackResultCard'
import { AttackSuggestionCard } from './AttackSuggestionCard'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AttackSuggestion {
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

interface AttackSurfaceSummary {
  services: { service: string; port: number; count: number }[]
  ports: { port: number; protocol: string; count: number }[]
  technologies: { name: string; version: string | null; cveCount: number }[]
  dnsRecords: { type: string; count: number }[]
  securityHeaders: { name: string; isSecurity: boolean; count: number }[]
  headerCategories: { category: string; count: number }[]
  endpointCategories: { category: string; count: number }[]
  endpointTypes: { type: string; count: number }[]
  parameterAnalysis: { position: string; total: number; injectable: number }[]
  cdnDistribution: { segment: string; count: number }[]
  ipConcentration: { ip: string; subCount: number; isCdn: boolean }[]
}

interface AttackPanelProps {
  projectId: string | null
  onTogglePartialReconLogs?: (runId: string) => void
  /** Called when the user chooses to escalate a successful attack to a reverse-shell session. */
  onRequestReverseShell?: (run: PartialReconState) => void
}

// ---------------------------------------------------------------------------
// Category config
// ---------------------------------------------------------------------------

const CATEGORY_CONFIG: Record<string, { label: string; icon: React.ReactNode; color: string }> = {
  recon: { label: 'Reconnaissance', icon: <Search size={14} />, color: 'var(--blue-500, #3b82f6)' },
  scan: { label: 'Vulnerability Scan', icon: <Bug size={14} />, color: 'var(--orange-500, #f59e0b)' },
  exploit: { label: 'Exploitation', icon: <Bug size={14} />, color: 'var(--red-500, #ef4444)' },
  enrich: { label: 'Enrichment', icon: <Package size={14} />, color: 'var(--purple-500, #a855f7)' },
}

const PRIORITY_LABELS: Record<number, string> = {
  0: 'Critical',
  1: 'High',
  2: 'Medium',
  3: 'Low',
}

const STATUS_LABELS: Record<PartialReconStatus, string> = {
  idle: 'Idle',
  starting: 'Starting…',
  running: 'Running…',
  paused: 'Paused',
  completed: 'Completed',
  error: 'Failed',
  stopping: 'Stopping…',
}

// ---------------------------------------------------------------------------
// Summary helpers
// ---------------------------------------------------------------------------

function sumBy<T>(items: T[], getter: (item: T) => number): number {
  return items.reduce((acc, item) => acc + (getter(item) || 0), 0)
}

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return `${n}`
}

function matchesSearch(suggestion: AttackSuggestion, query: string): boolean {
  if (!query.trim()) return true
  const q = query.toLowerCase()
  return (
    suggestion.title.toLowerCase().includes(q) ||
    suggestion.description.toLowerCase().includes(q) ||
    suggestion.toolId.toLowerCase().includes(q) ||
    suggestion.rationale.toLowerCase().includes(q) ||
    suggestion.prerequisites.some(p => p.toLowerCase().includes(q))
  )
}

function formatStatKey(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase())
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AttackPanel({ projectId, onTogglePartialReconLogs, onRequestReverseShell }: AttackPanelProps) {
  const toast = useToast()

  const [suggestions, setSuggestions] = useState<AttackSuggestion[]>([])
  const [surface, setSurface] = useState<AttackSurfaceSummary | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [surfaceLoading, setSurfaceLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [surfaceError, setSurfaceError] = useState<string | null>(null)
  const [activeFilter, setActiveFilter] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [ranAttacks, setRanAttacks] = useState<Set<string>>(new Set())
  const [runIdBySuggestion, setRunIdBySuggestion] = useState<Record<string, string>>({})
  const [isRunningAll, setIsRunningAll] = useState(false)
  const [dismissedRunIds, setDismissedRunIds] = useState<Set<string>>(new Set())
  const runsRef = useRef<PartialReconState[]>([])
  const prevSummaryValuesRef = useRef<Record<string, number>>({})

  // Fetch suggestions
  const fetchSuggestions = useCallback(async () => {
    if (!projectId) return
    setIsLoading(true)
    setError(null)
    try {
      const res = await fetch(`/api/recon/${projectId}/attacks/suggestions`)
      if (!res.ok) throw new Error('Failed to fetch suggestions')
      const data = await res.json()
      setSuggestions(data.suggestions || [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  // Fetch attack-surface analytics summary
  const fetchSurfaceSummary = useCallback(async () => {
    if (!projectId) return
    setSurfaceLoading(true)
    setSurfaceError(null)
    try {
      const res = await fetch(`/api/analytics/attack-surface?projectId=${encodeURIComponent(projectId)}`)
      if (!res.ok) throw new Error('Failed to fetch attack surface summary')
      const data = await res.json()
      setSurface(data)
    } catch (err) {
      setSurfaceError(err instanceof Error ? err.message : 'Unknown error')
    } finally {
      setSurfaceLoading(false)
    }
  }, [projectId])

  const handleRunComplete = useCallback(
    (runId: string) => {
      const run = runsRef.current.find((r: PartialReconState) => r.run_id === runId)
      const toolId = run?.tool_id
      const statsText = run?.stats
        ? Object.entries(run.stats)
            .slice(0, 3)
            .map(([k, v]) => `${formatStatKey(k)} ${v}`)
            .join(', ')
        : ''
      toast.success(
        statsText ? `${toolId || 'Attack'} finished — ${statsText}` : `${toolId || 'Attack'} finished`,
        'Results will appear in the graph',
      )
      fetchSuggestions()
      fetchSurfaceSummary()
    },
    [fetchSuggestions, fetchSurfaceSummary, toast],
  )

  const handleRunError = useCallback(
    (runId: string, runError: string) => {
      const toolId = runsRef.current.find((r: PartialReconState) => r.run_id === runId)?.tool_id
      toast.error(runError, toolId ? `${toolId} failed` : 'Attack failed')
    },
    [toast],
  )

  // Live partial-recon status polling
  const {
    runs,
    activeRuns,
    isAnyRunning,
    isLoading: isReconStatusLoading,
    error: reconStatusError,
    startPartialRecon,
    stopPartialRecon,
    refetch: refetchReconStatuses,
  } = useMultiPartialReconStatus({
    projectId,
    enabled: true,
    pollingInterval: 4000,
    onRunComplete: handleRunComplete,
    onRunError: handleRunError,
  })

  useEffect(() => {
    runsRef.current = runs
  }, [runs])

  useEffect(() => {
    fetchSuggestions()
    fetchSurfaceSummary()
  }, [fetchSuggestions, fetchSurfaceSummary])

  const handleRefresh = useCallback(() => {
    fetchSuggestions()
    fetchSurfaceSummary()
    refetchReconStatuses()
  }, [fetchSuggestions, fetchSurfaceSummary, refetchReconStatuses])

  // Run an attack
  const handleRunAttack = useCallback(
    async (suggestion: AttackSuggestion) => {
      if (!projectId) return

      try {
        const result = await startPartialRecon({
          tool_id: suggestion.toolId,
          graph_inputs: suggestion.graphInputs,
          user_inputs: [],
          include_graph_targets: true,
        })

        if (!result) {
          toast.error('Failed to start attack', suggestion.title)
          return
        }

        setRunIdBySuggestion(prev => ({ ...prev, [suggestion.id]: result.run_id }))
        setRanAttacks(prev => new Set(prev).add(suggestion.id))
        toast.info(`${suggestion.toolId} started`, suggestion.title)
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : 'Unknown error starting attack',
          suggestion.title,
        )
      }
    },
    [projectId, startPartialRecon, toast],
  )

  // Re-run a previously-completed suggestion
  const handleReRunAttack = useCallback(
    (suggestion: AttackSuggestion) => {
      // Clear the completed status so the card transitions to "run" state
      setRanAttacks(prev => {
        const next = new Set(prev)
        next.delete(suggestion.id)
        return next
      })
      handleRunAttack(suggestion)
    },
    [handleRunAttack],
  )

  // Stop an attack
  const handleStopAttack = useCallback(
    async (suggestion: AttackSuggestion) => {
      const runId = runIdBySuggestion[suggestion.id]
      if (!runId) return

      try {
        await stopPartialRecon(runId)
        toast.info(`${suggestion.toolId} stopped`, suggestion.title)
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : 'Failed to stop attack',
          suggestion.title,
        )
      }
    },
    [runIdBySuggestion, stopPartialRecon, toast],
  )

  // Stop all running attacks
  const handleStopAll = useCallback(async () => {
    const toStop = activeRuns.filter(r => r.run_id)
    if (toStop.length === 0) return

    toast.info(`Stopping ${toStop.length} attack${toStop.length === 1 ? '' : 's'}…`, 'Stop all')

    let errors = 0
    for (const run of toStop) {
      try {
        await stopPartialRecon(run.run_id)
      } catch {
        errors++
      }
    }

    if (errors > 0) {
      toast.error(`${errors} of ${toStop.length} attacks failed to stop`, 'Stop all')
    }
  }, [activeRuns, stopPartialRecon, toast])

  // Run all pending suggestions sequentially
  const handleRunAllPending = useCallback(async () => {
    if (!projectId || isAnyRunning || isRunningAll) return
    const pending = suggestions.filter(s => !s.alreadyRun && !runIdBySuggestion[s.id])
    if (pending.length === 0) return

    setIsRunningAll(true)
    toast.info(`Starting ${pending.length} pending attack${pending.length === 1 ? '' : 's'}`, 'Run all')

    let launched = 0
    let failed = 0
    try {
      for (const suggestion of pending) {
        try {
          // eslint-disable-next-line no-await-in-loop
          const result = await startPartialRecon({
            tool_id: suggestion.toolId,
            graph_inputs: suggestion.graphInputs,
            user_inputs: [],
            include_graph_targets: true,
          })
          if (result) {
            setRunIdBySuggestion(prev => ({ ...prev, [suggestion.id]: result.run_id }))
            setRanAttacks(prev => new Set(prev).add(suggestion.id))
            launched++
          } else {
            failed++
          }
        } catch {
          failed++
        }
        // Small delay between launches to avoid slamming the orchestrator
        // eslint-disable-next-line no-await-in-loop
        await new Promise(resolve => setTimeout(resolve, 250))
      }
    } finally {
      setIsRunningAll(false)
      if (failed > 0) {
        toast.error(`${failed} of ${pending.length} attacks failed to start`, 'Run all')
      }
    }
  }, [projectId, isAnyRunning, isRunningAll, suggestions, runIdBySuggestion, startPartialRecon, toast])

  // Retry a failed result by re-running its original suggestion
  const handleRetryResult = useCallback(
    (run: PartialReconState) => {
      // Find the suggestion that matches this run's tool_id
      const suggestion = suggestions.find(s => s.toolId === run.tool_id)
      if (!suggestion) {
        toast.error('Could not find matching attack suggestion for retry', run.tool_id)
        return
      }
      // Clear any prior state so the card shows as ready
      setDismissedRunIds(prev => {
        const next = new Set(prev)
        next.delete(run.run_id)
        return next
      })
      handleRunAttack(suggestion)
    },
    [suggestions, handleRunAttack, toast],
  )

  // Filter suggestions
  const filtered = useMemo(() => {
    const byCategory = activeFilter ? suggestions.filter(s => s.category === activeFilter) : suggestions
    return byCategory.filter(s => matchesSearch(s, searchQuery))
  }, [suggestions, activeFilter, searchQuery])

  // Counts
  const categoryCounts = suggestions.reduce<Record<string, number>>((acc, s) => {
    acc[s.category] = (acc[s.category] || 0) + 1
    return acc
  }, {})

  // Derived summary metrics
  const summaryMetrics = surface
    ? [
        { label: 'Services', value: surface.services.length, icon: <Server size={16} /> },
        { label: 'Open Ports', value: surface.ports.length, icon: <Network size={16} /> },
        { label: 'Technologies', value: surface.technologies.length, icon: <Cpu size={16} /> },
        { label: 'Endpoints', value: sumBy(surface.endpointCategories, c => c.count), icon: <Globe size={16} /> },
        { label: 'Parameters', value: sumBy(surface.parameterAnalysis, p => p.total), icon: <FileCode size={16} /> },
        { label: 'DNS Records', value: surface.dnsRecords.length, icon: <Target size={16} /> },
        { label: 'Security Headers', value: surface.securityHeaders.length, icon: <Shield size={16} /> },
        { label: 'CDN Segments', value: surface.cdnDistribution.length, icon: <Server size={16} /> },
      ]
    : []

  const hasSurfaceData = summaryMetrics.some(m => m.value > 0)

  // Track summary changes so we can show +N deltas after a refresh
  const deltas = useMemo(() => {
    const prev = prevSummaryValuesRef.current
    const next: Record<string, number> = {}
    for (const metric of summaryMetrics) {
      const prevValue = prev[metric.label]
      if (typeof prevValue === 'number' && metric.value > prevValue) {
        next[metric.label] = metric.value - prevValue
      }
    }
    return next
  }, [summaryMetrics])

  useEffect(() => {
    if (!surface) return
    const next: Record<string, number> = {}
    for (const metric of summaryMetrics) {
      next[metric.label] = metric.value
    }
    prevSummaryValuesRef.current = next
  }, [surface, summaryMetrics])

  // Helpers for run state display
  const getRunForSuggestion = useCallback(
    (suggestionId: string): PartialReconState | undefined => {
      const runId = runIdBySuggestion[suggestionId]
      if (!runId) return undefined
      return runs.find((r: PartialReconState) => r.run_id === runId)
    },
    [runIdBySuggestion, runs],
  )

  const pendingCount = suggestions.filter(s => !s.alreadyRun && !runIdBySuggestion[s.id]).length
  const canRunAll = pendingCount > 0 && !isAnyRunning && !isRunningAll && !isLoading

  // Recent terminal runs (completed or failed)
  const terminalRuns = useMemo(() => {
    const visible = runs.filter(r => (r.status === 'completed' || r.status === 'error') && !dismissedRunIds.has(r.run_id))
    return visible
      .sort((a, b) => {
        const aTime = a.completed_at ? new Date(a.completed_at).getTime() : 0
        const bTime = b.completed_at ? new Date(b.completed_at).getTime() : 0
        return bTime - aTime
      })
      .slice(0, 5)
  }, [runs, dismissedRunIds])

  const handleDismissResult = useCallback((runId: string) => {
    setDismissedRunIds(prev => new Set(prev).add(runId))
  }, [])

  const handleClearResults = useCallback(() => {
    setDismissedRunIds(prev => {
      const next = new Set(prev)
      for (const run of terminalRuns) {
        next.add(run.run_id)
      }
      return next
    })
  }, [terminalRuns])

  return (
    <section className={styles.container} aria-label="Attack Panel">
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <Target size={18} />
          <h2 className={styles.title}>Attack Surface Actions</h2>
          <span className={styles.badge}>{suggestions.length} suggested</span>
          {(isAnyRunning || activeRuns.length > 0) && (
            <span className={styles.runningBadge}>
              <Loader2 size={12} className={styles.spin} />
              {activeRuns.length} running
            </span>
          )}
        </div>
        <div className={styles.headerActions}>
          <div className={styles.searchBox}>
            <Search size={14} />
            <input
              type="text"
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="Search attacks…"
              className={styles.searchInput}
              aria-label="Search attack suggestions"
            />
            {searchQuery && (
              <button
                className={styles.searchClear}
                onClick={() => setSearchQuery('')}
                aria-label="Clear search"
              >
                <X size={12} />
              </button>
            )}
          </div>
          <button
            className={styles.refreshBtn}
            onClick={handleRefresh}
            disabled={isLoading || surfaceLoading || isReconStatusLoading}
            title="Refresh suggestions"
            aria-label="Refresh attack suggestions and surface summary"
          >
            <RefreshCw size={14} className={isLoading || surfaceLoading || isReconStatusLoading ? styles.spin : ''} />
          </button>
        </div>
      </div>

      {/* Attack surface summary */}
      {surfaceLoading && !surface ? (
        <div className={styles.summaryPlaceholder}>
          <Loader2 size={16} className={styles.spin} />
          <span>Loading attack surface summary…</span>
        </div>
      ) : surfaceError ? (
        <div className={styles.summaryPlaceholder}>
          <AlertCircle size={16} />
          <span>{surfaceError}</span>
        </div>
      ) : surface && hasSurfaceData ? (
        <div className={styles.summarySection}>
          <div className={styles.summaryTitle}>Attack Surface Overview</div>
          <div className={styles.summaryGrid}>
            {summaryMetrics.map(metric => (
              <AttackSurfaceSummaryCard
                key={metric.label}
                icon={metric.icon}
                label={metric.label}
                value={formatCount(metric.value)}
                delta={deltas[metric.label] ? formatCount(deltas[metric.label]) : undefined}
              />
            ))}
          </div>
        </div>
      ) : surface ? (
        <div className={styles.summaryPlaceholder}>
          <span>No attack-surface data has been collected yet.</span>
        </div>
      ) : null}

      {/* Recent results */}
      {terminalRuns.length > 0 && (
        <div className={styles.resultsSection}>
          <div className={styles.resultsHeader}>
            <span className={styles.resultsTitle}>Recent Results</span>
            <button className={styles.resultsClear} onClick={handleClearResults} aria-label="Clear results">
              Clear
            </button>
          </div>
          <div className={styles.resultsList}>
            {terminalRuns.map(run => (
              <AttackResultCard
                key={run.run_id}
                run={run}
                onShowLogs={onTogglePartialReconLogs}
                onCompleteReverseShell={onRequestReverseShell}
                onRetry={handleRetryResult}
                onDismiss={handleDismissResult}
              />
            ))}
          </div>
        </div>
      )}

      {/* Toolbar */}
      {suggestions.length > 0 && (
        <div className={styles.toolbar}>
          <button
            className={styles.runAllBtn}
            onClick={handleRunAllPending}
            disabled={!canRunAll}
            title={
              pendingCount === 0
                ? 'No pending attacks'
                : isAnyRunning
                  ? 'Wait for running attacks to finish'
                  : `Run all ${pendingCount} pending attacks`
            }
          >
            {isRunningAll ? <Loader2 size={14} className={styles.spin} /> : <Play size={14} />}
            <span>{isRunningAll ? 'Starting…' : `Run All Pending (${pendingCount})`}</span>
          </button>
          {activeRuns.length > 0 && (
            <button
              className={`${styles.stopAllBtn}`}
              onClick={handleStopAll}
              title={`Stop all ${activeRuns.length} running attack${activeRuns.length === 1 ? '' : 's'}`}
              aria-label={`Stop all ${activeRuns.length} running attacks`}
            >
              <Square size={14} fill="currentColor" />
              <span>Stop All ({activeRuns.length})</span>
            </button>
          )}
        </div>
      )}

      {/* Category filter pills */}
      {suggestions.length > 0 && (
        <CategoryFilterBar
          categories={CATEGORY_CONFIG}
          activeCategory={activeFilter}
          categoryCounts={categoryCounts}
          onCategoryChange={setActiveFilter}
        />
      )}

      {/* Error banners */}
      {error && (
        <div className={styles.errorBanner} role="alert">
          <AlertCircle size={14} />
          <span>{error}</span>
          <button onClick={() => setError(null)} className={styles.errorDismiss} aria-label="Dismiss error">&#x2715;</button>
        </div>
      )}
      {reconStatusError && (
        <div className={styles.errorBanner} role="alert">
          <AlertCircle size={14} />
          <span>{reconStatusError}</span>
          <button onClick={() => refetchReconStatuses()} className={styles.errorDismiss} title="Retry" aria-label="Retry fetching recon status">
            <RefreshCw size={12} />
          </button>
        </div>
      )}

      {/* Content */}
      <div className={styles.content}>
        {isLoading ? (
          <div className={styles.emptyState}>
            <Loader2 size={24} className={styles.spin} />
            <p>Analyzing attack surface...</p>
          </div>
        ) : suggestions.length === 0 ? (
          <div className={styles.emptyState}>
            <Target size={32} className={styles.emptyIcon} />
            <h3>No Attack Surface Actions Yet</h3>
            <p className={styles.emptyText}>
              Run a reconnaissance scan first to discover targets.
              Attack suggestions will appear here based on what&apos;s found.
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className={styles.emptyState}>
            <ListChecks size={32} className={styles.emptyIcon} />
            <h3>No matching suggestions</h3>
            <p className={styles.emptyText}>
              Try clearing your search or changing the active filter.
            </p>
          </div>
        ) : (
          <div className={styles.suggestionList}>
            {filtered.map(suggestion => {
              const cfg = CATEGORY_CONFIG[suggestion.category] || CATEGORY_CONFIG.recon
              const runState = getRunForSuggestion(suggestion.id)
              const isActive = !!(runState && (runState.status === 'starting' || runState.status === 'running'))
              const isAlreadyRun = !!(suggestion.alreadyRun || ranAttacks.has(suggestion.id))

              return (
                <AttackSuggestionCard
                  key={suggestion.id}
                  suggestion={suggestion}
                  categoryConfig={cfg}
                  priorityLabel={PRIORITY_LABELS[suggestion.priority]}
                  statusLabel={runState ? STATUS_LABELS[runState.status] : undefined}
                  isActive={isActive}
                  isAlreadyRun={isAlreadyRun}
                  runState={runState}
                  isAnyRunning={isAnyRunning}
                  isRunningAll={isRunningAll}
                  onRun={() => handleRunAttack(suggestion)}
                  onStop={() => handleStopAttack(suggestion)}
                  onReRun={() => handleReRunAttack(suggestion)}
                  onShowLogs={onTogglePartialReconLogs}
                />
              )
            })}
          </div>
        )}
      </div>
    </section>
  )
}

'use client'

import { useState, useEffect, useCallback } from 'react'
import {
  Target,
  Search,
  Loader2,
  CheckCircle2,
  AlertCircle,
  Play,
  Bug,
  Flag,
  Package,
  ListChecks,
  RefreshCw,
} from 'lucide-react'
import styles from './AttackPanel.module.css'

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

interface AttackPanelProps {
  projectId: string | null
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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AttackPanel({ projectId }: AttackPanelProps) {
  const [suggestions, setSuggestions] = useState<AttackSuggestion[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [runningAttack, setRunningAttack] = useState<string | null>(null)
  const [activeFilter, setActiveFilter] = useState<string | null>(null)
  const [ranAttacks, setRanAttacks] = useState<Set<string>>(new Set())

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

  useEffect(() => {
    fetchSuggestions()
  }, [fetchSuggestions])

  // Run an attack
  const handleRunAttack = useCallback(async (suggestion: AttackSuggestion) => {
    if (!projectId || runningAttack) return
    setRunningAttack(suggestion.id)

    try {
      const res = await fetch(`/api/recon/${projectId}/partial`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          tool_id: suggestion.toolId,
          graph_inputs: suggestion.graphInputs,
          user_inputs: [],
          include_graph_targets: true,
        }),
      })

      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.error || 'Failed to start attack')
      }

      setRanAttacks(prev => new Set(prev).add(suggestion.id))

      // Refresh suggestions to reflect new state
      setTimeout(fetchSuggestions, 2000)
    } catch (err) {
      console.error('[AttackPanel] Run error:', err)
      setError(err instanceof Error ? err.message : 'Failed to run attack')
    } finally {
      setRunningAttack(null)
    }
  }, [projectId, runningAttack, fetchSuggestions])

  // Filter suggestions
  const filtered = activeFilter
    ? suggestions.filter(s => s.category === activeFilter)
    : suggestions

  // Counts
  const categoryCounts = suggestions.reduce<Record<string, number>>((acc, s) => {
    acc[s.category] = (acc[s.category] || 0) + 1
    return acc
  }, {})

  return (
    <div className={styles.container}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <Target size={18} />
          <h2 className={styles.title}>Attack Surface Actions</h2>
          <span className={styles.badge}>{suggestions.length} suggested</span>
        </div>
        <button
          className={styles.refreshBtn}
          onClick={fetchSuggestions}
          disabled={isLoading}
          title="Refresh suggestions"
        >
          <RefreshCw size={14} className={isLoading ? styles.spin : ''} />
        </button>
      </div>

      {/* Category filter pills */}
      {suggestions.length > 0 && (
        <div className={styles.filters}>
          <button
            className={`${styles.filterPill} ${activeFilter === null ? styles.filterPillActive : ''}`}
            onClick={() => setActiveFilter(null)}
          >
            All
          </button>
          {Object.entries(CATEGORY_CONFIG).map(([key, cfg]) => (
            <button
              key={key}
              className={`${styles.filterPill} ${activeFilter === key ? styles.filterPillActive : ''}`}
              onClick={() => setActiveFilter(key)}
            >
              {cfg.icon}
              <span>{cfg.label}</span>
              {categoryCounts[key] && (
                <span className={styles.filterCount}>{categoryCounts[key]}</span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Error banner */}
      {error && (
        <div className={styles.errorBanner}>
          <AlertCircle size={14} />
          <span>{error}</span>
          <button onClick={() => setError(null)} className={styles.errorDismiss}>&#x2715;</button>
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
            <h3>No Attack Surface Yet</h3>
            <p className={styles.emptyText}>
              Run a reconnaissance scan first to discover targets.
              Attack suggestions will appear here based on what&apos;s found.
            </p>
          </div>
        ) : filtered.length === 0 ? (
          <div className={styles.emptyState}>
            <ListChecks size={32} className={styles.emptyIcon} />
            <h3>No {activeFilter ? CATEGORY_CONFIG[activeFilter]?.label : ''} Suggestions</h3>
            <p className={styles.emptyText}>
              No attacks in this category match the current scan data.
            </p>
          </div>
        ) : (
          <div className={styles.suggestionList}>
            {filtered.map(suggestion => {
              const cfg = CATEGORY_CONFIG[suggestion.category] || CATEGORY_CONFIG.recon
              const isRunning = runningAttack === suggestion.id
              const isAlreadyRun = suggestion.alreadyRun || ranAttacks.has(suggestion.id)

              return (
                <div
                  key={suggestion.id}
                  className={`${styles.card} ${isAlreadyRun ? styles.cardDone : ''}`}
                >
                  {/* Left accent bar */}
                  <div className={styles.cardAccent} style={{ backgroundColor: cfg.color }} />

                  <div className={styles.cardBody}>
                    {/* Header row */}
                    <div className={styles.cardHeader}>
                      <div className={styles.cardTitleRow}>
                        <span className={styles.categoryBadge} style={{ color: cfg.color }}>
                          {cfg.icon}
                          <span>{cfg.label}</span>
                        </span>
                        <span className={`${styles.priorityBadge} ${styles[`priority${suggestion.priority}`]}`}>
                          {PRIORITY_LABELS[suggestion.priority]}
                        </span>
                      </div>
                      <h3 className={styles.cardTitle}>{suggestion.title}</h3>
                      <p className={styles.cardDesc}>{suggestion.description}</p>
                    </div>

                    {/* Rationale + meta row */}
                    <div className={styles.cardMeta}>
                      <div className={styles.rationale}>
                        <Flag size={12} />
                        <span>{suggestion.rationale}</span>
                      </div>
                      <div className={styles.stats}>
                        <span className={styles.stat}>
                          <Target size={12} />
                          {suggestion.matchedNodeCount} targets
                        </span>
                        {suggestion.prerequisites.map(p => (
                          <span key={p} className={styles.prereq}>{p}</span>
                        ))}
                      </div>
                    </div>

                    {/* Action row */}
                    <div className={styles.cardActions}>
                      {isAlreadyRun ? (
                        <span className={styles.doneLabel}>
                          <CheckCircle2 size={14} />
                          Already completed
                        </span>
                      ) : (
                        <button
                          className={styles.runBtn}
                          onClick={() => handleRunAttack(suggestion)}
                          disabled={isRunning}
                        >
                          {isRunning ? (
                            <Loader2 size={14} className={styles.spin} />
                          ) : (
                            <Play size={14} />
                          )}
                          <span>{isRunning ? 'Starting...' : 'Run Attack'}</span>
                        </button>
                      )}
                      <span className={styles.toolId}>via {suggestion.toolId}</span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}

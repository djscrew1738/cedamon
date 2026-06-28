'use client'

import { AlertCircle, CheckCircle2, Clock, TrendingUp, ScrollText, Terminal, X, RotateCcw } from 'lucide-react'
import styles from './AttackPanel.module.css'
import type { PartialReconState } from '@/lib/recon-types'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface AttackResultCardProps {
  run: PartialReconState
  onShowLogs?: (runId: string) => void
  onCompleteReverseShell?: (run: PartialReconState) => void
  onRetry?: (run: PartialReconState) => void
  onDismiss: (runId: string) => void
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`
  return `${n}`
}

function formatStatKey(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase())
}

function formatTimestamp(iso: string | null): string {
  if (!iso) return ''
  try {
    const date = new Date(iso)
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  } catch {
    return iso
  }
}

const EXPLOITABLE_STAT_KEYS = ['vulnerabilities_found', 'critical', 'high', 'exploited', 'rce_found', 'shells']

function hasExploitableFindings(run: PartialReconState): boolean {
  if (run.status !== 'completed') return false
  if (!run.stats) return false
  return EXPLOITABLE_STAT_KEYS.some(key => {
    const value = run.stats?.[key]
    return typeof value === 'number' && value > 0
  })
}

function renderRunStats(stats: Record<string, number> | null): React.ReactNode {
  if (!stats || Object.keys(stats).length === 0) return null
  return (
    <div className={styles.resultStats}>
      {Object.entries(stats).map(([key, value]) => (
        <span key={key} className={styles.resultStat}>
          <TrendingUp size={10} />
          {formatStatKey(key)}: {formatCount(value)}
        </span>
      ))}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AttackResultCard({ run, onShowLogs, onCompleteReverseShell, onRetry, onDismiss }: AttackResultCardProps) {
  const isError = run.status === 'error'

  return (
    <div className={`${styles.resultCard} ${isError ? styles.resultError : ''}`}>
      <div className={styles.resultIcon}>
        {isError ? <AlertCircle size={16} /> : <CheckCircle2 size={16} />}
      </div>
      <div className={styles.resultBody}>
        <div className={styles.resultTop}>
          <span className={styles.resultTool}>{run.tool_id}</span>
          <span className={`${styles.resultStatus} ${isError ? styles.resultStatusError : styles.resultStatusSuccess}`}>
            {isError ? 'Failed' : 'Completed'}
          </span>
          {run.completed_at && (
            <span className={styles.resultTime}>
              <Clock size={10} />
              {formatTimestamp(run.completed_at)}
            </span>
          )}
        </div>
        {run.error && <div className={styles.resultErrorText}>{run.error}</div>}
        {renderRunStats(run.stats)}
      </div>
      <div className={styles.resultActions}>
        {onShowLogs && (
          <button
            className={styles.ghostBtn}
            onClick={() => onShowLogs(run.run_id)}
            title="View logs"
            aria-label={`View logs for ${run.tool_id}`}
          >
            <ScrollText size={14} />
          </button>
        )}
        {hasExploitableFindings(run) && onCompleteReverseShell && (
          <button
            className={styles.shellBtn}
            onClick={() => onCompleteReverseShell(run)}
            title="Escalate to reverse shell"
            aria-label={`Escalate ${run.tool_id} to reverse shell`}
          >
            <Terminal size={14} />
            <span>Reverse Shell</span>
          </button>
        )}
        {isError && onRetry && (
          <button
            className={styles.retryBtn}
            onClick={() => onRetry(run)}
            title="Retry this attack"
            aria-label={`Retry ${run.tool_id}`}
          >
            <RotateCcw size={14} />
            <span>Retry</span>
          </button>
        )}
        <button
          className={styles.resultDismiss}
          onClick={() => onDismiss(run.run_id)}
          title="Dismiss"
          aria-label={`Dismiss ${run.tool_id} result`}
        >
          <X size={14} />
        </button>
      </div>
    </div>
  )
}

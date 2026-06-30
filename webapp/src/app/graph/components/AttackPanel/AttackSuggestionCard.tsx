'use client'

import {
  Target,
  Flag,
  CheckCircle2,
  XCircle,
  Play,
  Square,
  ScrollText,
} from 'lucide-react'
import styles from './AttackPanel.module.css'
import type { PartialReconState } from '@/lib/recon-types'

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

interface AttackSuggestionCardProps {
  suggestion: AttackSuggestion
  categoryConfig: { label: string; icon: React.ReactNode; color: string }
  priorityLabel: string
  statusLabel?: string
  isActive: boolean
  isAlreadyRun: boolean
  runState?: PartialReconState
  isAnyRunning: boolean
  isRunningAll: boolean
  onRun: () => void
  onStop: () => void
  onReRun?: () => void
  onShowLogs?: (runId: string) => void
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function AttackSuggestionCard({
  suggestion,
  categoryConfig: cfg,
  priorityLabel,
  statusLabel,
  isActive,
  isAlreadyRun,
  runState,
  isAnyRunning,
  isRunningAll,
  onRun,
  onStop,
  onReRun,
  onShowLogs,
}: AttackSuggestionCardProps) {
  return (
    <div
      className={`${styles.card} ${isAlreadyRun && !isActive ? styles.cardDone : ''}`}
      style={{ '--card-accent': cfg.color } as React.CSSProperties}
    >
      {/* Left accent bar */}
      <div className={styles.cardAccent} />

      <div className={styles.cardBody}>
        {/* Header row */}
        <div className={styles.cardHeader}>
          <div className={styles.cardTitleRow}>
            <span className={styles.categoryBadge}>
              {cfg.icon}
              <span>{cfg.label}</span>
            </span>
            <span className={`${styles.priorityBadge} ${styles[`priority${suggestion.priority}`]}`}>
              {priorityLabel}
            </span>
            {runState && (
              <span
                className={`${styles.statusBadge} ${styles[`status${runState.status}`]}`}
                title={runState.error || undefined}
              >
                {statusLabel}
              </span>
            )}
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
          {isActive ? (
            <>
              <button
                className={`${styles.runBtn} ${styles.stopBtn}`}
                onClick={onStop}
              >
                <Square size={14} fill="currentColor" />
                <span>Stop</span>
              </button>
              {onShowLogs && runState && (
                <button
                  className={styles.ghostBtn}
                  onClick={() => onShowLogs(runState.run_id)}
                >
                  <ScrollText size={14} />
                  <span>Logs</span>
                </button>
              )}
            </>
          ) : isAlreadyRun ? (
            onReRun ? (
              <button
                className={styles.runBtn}
                onClick={onReRun}
                disabled={isAnyRunning || isRunningAll}
              >
                <Play size={14} />
                <span>Re-run</span>
              </button>
            ) : runState?.status === 'error' ? (
              <span className={styles.failedLabel}>
                <XCircle size={14} />
                Failed — {runState.error?.slice(0, 60) || 'Unknown error'}
              </span>
            ) : (
              <span className={styles.doneLabel}>
                <CheckCircle2 size={14} />
                Completed successfully
              </span>
            )
          ) : (
            <button
              className={styles.runBtn}
              onClick={onRun}
              disabled={isAnyRunning || isRunningAll}
            >
              <Play size={14} />
              <span>Run Attack</span>
            </button>
          )}
          <span className={styles.toolId}>via {suggestion.toolId}</span>
        </div>
      </div>
    </div>
  )
}

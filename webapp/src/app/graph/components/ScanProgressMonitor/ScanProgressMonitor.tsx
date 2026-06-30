'use client'

import { useState, useCallback, useEffect, useRef } from 'react'
import { Loader2, ChevronDown, ChevronUp, CheckCircle2, XCircle } from 'lucide-react'
import styles from './ScanProgressMonitor.module.css'

export interface ActiveScan {
  label: string
  status: string
  phase?: string | null
  phaseNumber?: number | null
  totalPhases?: number
  elapsed?: string | null
}

interface ScanProgressMonitorProps {
  scans: ActiveScan[]
}

function statusColor(status: string): string {
  switch (status) {
    case 'running': return styles.dotRunning
    case 'starting': return styles.dotStarting
    case 'paused': return styles.dotPaused
    case 'error': return styles.dotError
    case 'completed': return styles.dotCompleted
    default: return styles.dotIdle
  }
}

export function ScanProgressMonitor({ scans }: ScanProgressMonitorProps) {
  const [expanded, setExpanded] = useState(false)
  const [completedToast, setCompletedToast] = useState<string | null>(null)

  const prevScansRef = useRef<ActiveScan[]>([])

  // Detect scan completions and show summary
  useEffect(() => {
    const prevMap = new Map(prevScansRef.current.map(s => [s.label, s.status]))
    for (const scan of scans) {
      const prevStatus = prevMap.get(scan.label)
      if (prevStatus && prevStatus !== 'completed' && scan.status === 'completed') {
        setCompletedToast(scan.label)
        setTimeout(() => setCompletedToast(null), 6000)
      }
    }
    prevScansRef.current = scans
  }, [scans])

  const activeScans = scans.filter(
    s => s.status === 'running' || s.status === 'starting' || s.status === 'paused'
  )

  const toggle = useCallback(() => {
    if (activeScans.length > 0) setExpanded(prev => !prev)
  }, [activeScans.length])

  if (activeScans.length === 0 && !completedToast) return null

  return (
    <div className={styles.wrapper}>
      {/* Completion toast */}
      {completedToast && (
        <div className={styles.completionToast}>
          <CheckCircle2 size={14} className={styles.completionIcon} />
          <span className={styles.completionText}>
            {completedToast} completed
          </span>
          <button
            className={styles.completionDismiss}
            onClick={() => setCompletedToast(null)}
            aria-label="Dismiss"
          >
            <XCircle size={14} />
          </button>
        </div>
      )}

      {/* Collapsed trigger badge */}
      {activeScans.length > 0 && (
        <button
          className={styles.trigger}
          onClick={toggle}
          title={expanded ? 'Hide scan details' : 'Show scan details'}
          aria-expanded={expanded}
        >
          <Loader2 size={12} className={styles.spinner} />
          <span className={styles.triggerLabel}>
            {activeScans.length} scan{activeScans.length > 1 ? 's' : ''} active
          </span>
          {expanded
            ? <ChevronUp size={12} className={styles.chevron} />
            : <ChevronDown size={12} className={styles.chevron} />
          }
        </button>
      )}

      {/* Expanded scan list */}
      {expanded && (
        <div className={styles.dropdown}>
          {activeScans.map((scan, idx) => {
            const total = scan.totalPhases ?? 1
            const current = Math.max(1, Math.min(scan.phaseNumber ?? 1, total))
            const percent = Math.round((current / total) * 100)

            return (
              <div key={`${scan.label}-${idx}`} className={styles.scanRow}>
                <div className={styles.scanRowHeader}>
                  <span className={`${styles.statusDot} ${statusColor(scan.status)}`} />
                  <span className={styles.scanRowLabel}>{scan.label}</span>
                  {scan.elapsed && (
                    <span className={styles.scanRowElapsed}>{scan.elapsed}</span>
                  )}
                  {scan.status === 'paused' && (
                    <span className={styles.pausedTag}>Paused</span>
                  )}
                </div>
                {scan.phase && (
                  <div className={styles.scanRowPhase}>
                    <span>Phase {current}/{total}: {scan.phase}</span>
                  </div>
                )}
                <div className={styles.progressTrack}>
                  <div
                    className={styles.progressFill}
                    style={{ width: `${percent}%` }}
                  />
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default ScanProgressMonitor

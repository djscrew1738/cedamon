'use client'

import { useState, useCallback } from 'react'
import { Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import styles from './ScanProgressMonitor.module.css'

export interface ActiveScan {
  label: string
  status: string
  phase?: string | null
  phaseNumber?: number | null
  totalPhases?: number
  /** Optional human-readable elapsed time string (e.g. "2m 34s") */
  elapsed?: string | null
}

interface ScanProgressMonitorProps {
  scans: ActiveScan[]
}

/**
 * Map a scan status to a colour class for the status dot.
 */
function statusColor(status: string): string {
  switch (status) {
    case 'running':
      return styles.dotRunning
    case 'starting':
      return styles.dotStarting
    case 'paused':
      return styles.dotPaused
    case 'error':
    case 'stopping':
      return styles.dotError
    default:
      return styles.dotIdle
  }
}

export function ScanProgressMonitor({ scans }: ScanProgressMonitorProps) {
  const [expanded, setExpanded] = useState(false)

  const activeScans = scans.filter(
    s => s.status === 'running' || s.status === 'starting' || s.status === 'paused'
  )

  const toggle = useCallback(() => {
    if (activeScans.length > 0) setExpanded(prev => !prev)
  }, [activeScans.length])

  if (activeScans.length === 0) return null

  return (
    <div className={styles.wrapper}>
      {/* Collapsed trigger badge */}
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

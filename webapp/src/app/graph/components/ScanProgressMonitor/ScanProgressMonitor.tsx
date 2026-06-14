'use client'

import { Loader2 } from 'lucide-react'
import styles from './ScanProgressMonitor.module.css'

export interface ActiveScan {
  label: string
  status: string
  phase?: string | null
  phaseNumber?: number | null
  totalPhases?: number
}

interface ScanProgressMonitorProps {
  scans: ActiveScan[]
}

export function ScanProgressMonitor({ scans }: ScanProgressMonitorProps) {
  const activeScans = scans.filter(
    s => s.status === 'running' || s.status === 'starting' || s.status === 'paused'
  )

  if (activeScans.length === 0) return null

  // Show the first active scan; the toolbar has limited horizontal real estate.
  const scan = activeScans[0]
  const total = scan.totalPhases ?? 1
  const current = Math.max(1, Math.min(scan.phaseNumber ?? 1, total))
  const percent = Math.round((current / total) * 100)

  return (
    <div className={styles.monitor}>
      <Loader2 size={12} className={styles.spinner} />
      <div className={styles.info}>
        <span className={styles.label}>{scan.label}</span>
        {scan.phase && (
          <span className={styles.phase}>
            Phase {current}/{total}: {scan.phase}
          </span>
        )}
      </div>
      <div className={styles.progressTrack}>
        <div
          className={styles.progressFill}
          style={{ width: `${percent}%` }}
        />
      </div>
      {activeScans.length > 1 && (
        <span className={styles.moreBadge}>+{activeScans.length - 1}</span>
      )}
    </div>
  )
}

export default ScanProgressMonitor

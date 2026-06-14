'use client'

import { Play, Pause, Square, Terminal, Download, Loader2 } from 'lucide-react'
import type { ReactNode } from 'react'
import styles from './OtherScansModal.module.css'

export interface ScanCardProps {
  icon: ReactNode
  title: string
  description: string
  status: string
  isAvailable?: boolean
  unavailableMessage?: ReactNode
  requiresReconData?: boolean
  hasReconData?: boolean
  requiresGithubToken?: boolean
  hasGithubToken?: boolean
  onStart: () => void
  onPause?: () => void
  onResume?: () => void
  onStop: () => void
  onToggleLogs?: () => void
  onDownload?: () => void
  isLogsOpen?: boolean
  hasData?: boolean
  startLabel?: string
  pauseLabel?: string
  resumeLabel?: string
  stopLabel?: string
  logsLabel?: string
  downloadLabel?: string
  busyLabel?: string
}

function StatusBadge({ status }: { status: string }) {
  const styleMap: Record<string, string> = {
    idle: styles.statusIdle,
    starting: styles.statusRunning,
    running: styles.statusRunning,
    paused: styles.statusPaused,
    stopping: styles.statusRunning,
    completed: styles.statusCompleted,
    error: styles.statusError,
  }
  return (
    <span className={`${styles.statusBadge} ${styleMap[status] || styles.statusIdle}`}>
      {status}
    </span>
  )
}

export function ScanCard({
  icon,
  title,
  description,
  status,
  isAvailable = true,
  unavailableMessage,
  requiresReconData = false,
  hasReconData = false,
  requiresGithubToken = false,
  hasGithubToken = false,
  onStart,
  onPause,
  onResume,
  onStop,
  onToggleLogs,
  onDownload,
  isLogsOpen = false,
  hasData = false,
  startLabel = 'Start',
  pauseLabel = 'Pause',
  resumeLabel = 'Resume',
  stopLabel = 'Stop',
  logsLabel = 'Logs',
  downloadLabel = 'Download',
  busyLabel = 'Running...',
}: ScanCardProps) {
  const isBusy = status === 'running' || status === 'starting'
  const isStopping = status === 'stopping'
  const isRunning = isBusy || isStopping
  const isPaused = status === 'paused'
  const isActive = isRunning || isPaused

  const tokenMissing = requiresGithubToken && !hasGithubToken
  const reconMissing = requiresReconData && !hasReconData
  const startDisabled = !isAvailable || tokenMissing || reconMissing || isRunning || isPaused

  const startTooltip = !isAvailable
    ? (typeof unavailableMessage === 'string' ? unavailableMessage : 'Scan unavailable')
    : tokenMissing
    ? 'GitHub token required'
    : reconMissing
    ? 'Run recon first'
    : isRunning
    ? 'In progress...'
    : isPaused
    ? resumeLabel
    : startLabel

  return (
    <div className={styles.card}>
      <div className={styles.cardHeader}>
        {icon}
        <h3 className={styles.cardTitle}>{title}</h3>
        <StatusBadge status={status} />
      </div>
      <p className={styles.cardDescription}>{description}</p>
      {!isAvailable && unavailableMessage && (
        <div className={styles.unavailableBanner}>{unavailableMessage}</div>
      )}
      <div className={styles.cardActions}>
        {isPaused && onResume ? (
          <button
            className={styles.resumeButton}
            onClick={onResume}
            disabled={tokenMissing}
            title={startTooltip}
            aria-label={`${resumeLabel} ${title}`}
          >
            <Play size={12} />
            <span>{resumeLabel}</span>
          </button>
        ) : (
          <button
            className={styles.startButton}
            onClick={onStart}
            disabled={startDisabled}
            title={startTooltip}
            aria-label={`${isBusy ? busyLabel : isStopping ? 'Stopping' : startLabel} ${title}`}
          >
            {isRunning ? (
              <Loader2 size={12} className={styles.spinner} />
            ) : (
              <Play size={12} />
            )}
            <span>{isBusy ? busyLabel : isStopping ? 'Stopping...' : startLabel}</span>
          </button>
        )}

        {isBusy && onPause && (
          <button
            className={styles.pauseButton}
            onClick={onPause}
            title={pauseLabel}
            aria-label={`${pauseLabel} ${title}`}
          >
            <Pause size={12} />
            <span>{pauseLabel}</span>
          </button>
        )}

        {isActive && (
          <button
            className={styles.stopButton}
            onClick={onStop}
            disabled={isStopping}
            title={stopLabel}
            aria-label={`${stopLabel} ${title}`}
          >
            <Square size={12} />
            <span>{stopLabel}</span>
          </button>
        )}

        {onToggleLogs && (
          <button
            className={`${styles.logsButton} ${isLogsOpen ? styles.logsButtonActive : ''}`}
            onClick={onToggleLogs}
            disabled={!isActive}
            title={isActive ? 'View Logs' : 'No active scan'}
            aria-label={`${logsLabel} ${title}`}
          >
            <Terminal size={12} />
            <span>{logsLabel}</span>
          </button>
        )}

        {onDownload && (
          <button
            className={styles.downloadButton}
            onClick={onDownload}
            disabled={!hasData || isActive}
            title={hasData ? 'Download JSON' : 'No data available'}
            aria-label={`${downloadLabel} ${title}`}
          >
            <Download size={12} />
            <span>{downloadLabel}</span>
          </button>
        )}
      </div>
    </div>
  )
}

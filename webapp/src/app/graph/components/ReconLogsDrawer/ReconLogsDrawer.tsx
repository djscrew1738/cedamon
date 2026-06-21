'use client'

import { useEffect, useRef, useState, useCallback } from 'react'
import { X, Terminal, CheckCircle, AlertCircle, Pause, Play, Trash2, Square, Loader2, Download } from 'lucide-react'
import { RECON_PHASES } from '@/lib/recon-types'
import type { ReconLogEvent, ReconStatus } from '@/lib/recon-types'
import tabStyles from '@/app/graph/components/PartialReconLogsDrawer/PartialReconLogsDrawer.module.css'
import styles from './ReconLogsDrawer.module.css'

// Highlight the union target-list breakdown emitted by build_target_urls
// (e.g. "[*][Targets] Merged 50 URLs: 2 additional httpx URLs + 48 unprobed
// subdomains"). Easy to spot when scrolling through verbose scan logs.
const isTargetsLine = (logText: string) =>
  logText.includes('[Targets]') &&
  (logText.includes('Merged ') || logText.includes('No targets'))

// Highlight vulnerability findings in bright green so they stand out in
// verbose scan logs. Matches RedAmon summaries (e.g. "[+][Nuclei] Vuln
// findings: ..."), severity counts, Nmap NSE VULN lines, Nuclei severity
// tags (e.g. "[critical]"), and literal CVE identifiers.
export const isVulnerabilityLine = (logText: string) =>
  /\[\+\].*\b(?:vulns?|vulnerabilit(?:y|ies)|VULN|VULNERABLE|CVE-\d{4}-\d+)|VULN:|\b(?:CRITICAL|HIGH|MEDIUM|LOW):\s*\d+|\[(?:critical|high|medium|low)\]/i.test(
    logText
  )

/** Per-tab configuration passed to the multi-tab drawer. */
export interface LogTab {
  id: string
  label: string
  status: ReconStatus
  logs: ReconLogEvent[]
  currentPhase: string | null
  currentPhaseNumber: number | null
  errorMessage?: string | null
  phases?: readonly string[]
  totalPhases?: number
  hidePhaseProgress?: boolean
  isConnected?: boolean
  isReconnecting?: boolean
}

interface ReconLogsDrawerProps {
  isOpen: boolean
  onClose: () => void
  /** When provided, the drawer renders in multi-tab mode. */
  tabs?: LogTab[]
  activeTabId?: string
  onTabChange?: (tabId: string) => void
  onTabClose?: (tabId: string) => void
  onClearLogs: (tabId: string) => void
  onPause?: (tabId: string) => void
  onResume?: (tabId: string) => void
  onStop?: (tabId: string) => void
  onDownloadLogs?: (tabId: string) => void
  /** Legacy single-tab props — used only when tabs is not provided. */
  logs?: ReconLogEvent[]
  currentPhase?: string | null
  currentPhaseNumber?: number | null
  status?: ReconStatus
  title?: string
  phases?: readonly string[]
  totalPhases?: number
  errorMessage?: string | null
  hidePhaseProgress?: boolean
  isConnected?: boolean
  isReconnecting?: boolean
}

function getTabDotClass(status: string): string {
  switch (status) {
    case 'running':
    case 'starting':
    case 'stopping':
      return tabStyles.tabDotRunning
    case 'completed':
      return tabStyles.tabDotCompleted
    case 'error':
      return tabStyles.tabDotError
    default:
      return tabStyles.tabDotIdle
  }
}

export function ReconLogsDrawer(props: ReconLogsDrawerProps) {
  const {
    isOpen,
    onClose,
    tabs,
    activeTabId,
    onTabChange,
    onTabClose,
    onClearLogs,
    onPause,
    onResume,
    onStop,
    onDownloadLogs,
  } = props

  const logsEndRef = useRef<HTMLDivElement>(null)
  const logsContainerRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)

  const isMultiTab = tabs !== undefined && tabs.length > 0

  // Resolve the active tab data
  const activeTab = isMultiTab
    ? tabs.find(t => t.id === activeTabId) ?? tabs[0] ?? null
    : null

  // Use active tab data or fall back to legacy single-tab props
  const {
    logs = [],
    status = 'idle',
    currentPhase = null,
    currentPhaseNumber = null,
    errorMessage = null,
    phases = RECON_PHASES,
    totalPhases = 7,
    hidePhaseProgress = false,
    isConnected = false,
    isReconnecting = false,
  } = activeTab ?? props

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [logs, autoScroll])

  // Detect manual scroll to disable auto-scroll
  const handleScroll = useCallback(() => {
    if (!logsContainerRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = logsContainerRef.current
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 50
    setAutoScroll(isAtBottom)
  }, [])

  const getStatusIcon = () => {
    switch (status) {
      case 'running':
      case 'starting':
        return <div className={styles.runningIndicator} />
      case 'paused':
        return <Pause size={14} className={styles.pausedIcon} />
      case 'stopping':
        return <Loader2 size={14} className={styles.spinner} />
      case 'completed':
        return <CheckCircle size={14} className={styles.successIcon} />
      case 'error':
        return <AlertCircle size={14} className={styles.errorIcon} />
      default:
        return <Terminal size={14} />
    }
  }

  const getStatusText = () => {
    switch (status) {
      case 'starting':
        return 'Starting...'
      case 'running':
        if (!currentPhase) return 'Running...'
        return hidePhaseProgress
          ? `Scanning: ${currentPhase}`
          : `Phase ${currentPhaseNumber}/${totalPhases}: ${currentPhase}`
      case 'paused':
        if (!currentPhase) return 'Paused'
        return hidePhaseProgress
          ? `Paused: ${currentPhase}`
          : `Paused — Phase ${currentPhaseNumber}/${totalPhases}: ${currentPhase}`
      case 'completed':
        return 'Completed'
      case 'error':
        return errorMessage ? `Error: ${errorMessage}` : 'Error'
      case 'stopping':
        return 'Stopping...'
      default:
        return 'Idle'
    }
  }

  const handleDownloadLogs = useCallback(() => {
    if (logs.length === 0) return
    const tabId = activeTab?.id ?? 'logs'
    const label = activeTab?.label ?? 'Logs'

    const lines = logs.map((log: ReconLogEvent) => {
      const ts = new Date(log.timestamp).toISOString()
      const level = log.level.toUpperCase().padEnd(7)
      const phase = log.phase ? ` [${log.phase}]` : ''
      return `${ts}  ${level}${phase}  ${log.log}`
    })

    const header = [
      `# ${label}`,
      `# Status: ${status}`,
      `# Phase: ${currentPhase || 'N/A'} (${currentPhaseNumber || 0}/${totalPhases})`,
      `# Exported: ${new Date().toISOString()}`,
      `# Total lines: ${logs.length}`,
      '',
    ]

    const content = [...header, ...lines].join('\n')
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const safeName = label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/_+$/, '')
    a.download = `${safeName}_${new Date().toISOString().slice(0, 19).replace(/:/g, '-')}.log`
    a.click()
    URL.revokeObjectURL(url)

    if (onDownloadLogs) onDownloadLogs(tabId)
  }, [logs, activeTab, status, currentPhase, currentPhaseNumber, totalPhases, onDownloadLogs])

  const getLogClassName = (level: string) => {
    switch (level) {
      case 'error':
        return styles.logError
      case 'warning':
        return styles.logWarning
      case 'success':
        return styles.logSuccess
      case 'action':
        return styles.logAction
      default:
        return styles.logInfo
    }
  }

  const handleClearLogs = useCallback(() => {
    const tabId = activeTab?.id ?? 'recon'
    onClearLogs(tabId)
  }, [activeTab, onClearLogs])

  const handlePause = useCallback(() => {
    const tabId = activeTab?.id ?? 'recon'
    if (onPause) onPause(tabId)
  }, [activeTab, onPause])

  const handleResume = useCallback(() => {
    const tabId = activeTab?.id ?? 'recon'
    if (onResume) onResume(tabId)
  }, [activeTab, onResume])

  const handleStop = useCallback(() => {
    const tabId = activeTab?.id ?? 'recon'
    if (onStop) onStop(tabId)
  }, [activeTab, onStop])

  const handleTabClose = useCallback((e: React.MouseEvent, tabId: string) => {
    e.stopPropagation()
    if (onTabClose) onTabClose(tabId)
  }, [onTabClose])

  const drawerTitle = isMultiTab ? 'Scan Logs' : (props.title || 'Reconnaissance Logs')

  return (
    <div className={`${styles.drawer} ${isOpen ? styles.drawerOpen : ''}`}>
      {/* Header */}
      <div className={styles.header}>
        <div className={styles.titleContainer}>
          <Terminal size={16} />
          <span>{drawerTitle}</span>
          {isMultiTab && tabs && tabs.length > 1 && (
            <span className={styles.tabCount}>{tabs.length} tabs</span>
          )}
        </div>
        <button
          className={styles.closeButton}
          onClick={onClose}
          aria-label="Close drawer"
        >
          <X size={16} />
        </button>
      </div>

      {/* Tab bar (multi-tab mode only) */}
      {isMultiTab && tabs && (
        <div className={tabStyles.tabBar} role="tablist">
          {tabs.map(tab => (
            <button
              key={tab.id}
              role="tab"
              aria-selected={tab.id === activeTab?.id}
              className={`${tabStyles.tab} ${tab.id === activeTab?.id ? tabStyles.tabActive : ''}`}
              onClick={() => onTabChange?.(tab.id)}
            >
              <span className={`${tabStyles.tabDot} ${getTabDotClass(tab.status)}`} />
              <span>{tab.label}</span>
              {(tab.status === 'running' || tab.status === 'starting') && (
                <Loader2 size={10} className={styles.spinner} />
              )}
              {tabs.length > 1 && (
                <span
                  className={tabStyles.tabClose}
                  onClick={(e) => handleTabClose(e, tab.id)}
                  title={`Close ${tab.label}`}
                >
                  <X size={10} />
                </span>
              )}
            </button>
          ))}
        </div>
      )}

      {/* Status bar */}
      <div className={styles.statusBar}>
        <div className={styles.statusLeft}>
          {isMultiTab && activeTab && (
            <span className={tabStyles.statusTabName}>{activeTab.label}</span>
          )}
          {getStatusIcon()}
          <span className={styles.statusText} title={getStatusText()}>{getStatusText()}</span>
          {(status === 'running' || status === 'starting' || status === 'paused' || status === 'stopping') && (
            <span
              className={`${styles.connectionBadge} ${isConnected ? styles.connectionConnected : isReconnecting ? styles.connectionReconnecting : styles.connectionDisconnected}`}
              title={isConnected ? 'Live log stream connected' : isReconnecting ? 'Reconnecting to log stream...' : 'Disconnected'}
            >
              <span className={styles.connectionDot} />
              {isConnected ? 'Live' : isReconnecting ? 'Reconnecting' : 'Disconnected'}
            </span>
          )}
        </div>
        <div className={styles.statusActions}>
          {(status === 'running' || status === 'paused') && (
            <button
              className={`${styles.iconButton} ${status === 'paused' ? styles.iconButtonPaused : ''}`}
              onClick={status === 'paused' ? handleResume : handlePause}
              title={status === 'paused' ? 'Resume pipeline' : 'Pause pipeline'}
            >
              {status === 'paused' ? <Play size={14} /> : <Pause size={14} />}
            </button>
          )}
          {(status === 'running' || status === 'paused') && (
            <button
              className={`${styles.iconButton} ${styles.iconButtonStop}`}
              onClick={handleStop}
              title="Stop pipeline"
            >
              <Square size={14} />
            </button>
          )}
          <button
            className={styles.iconButton}
            onClick={handleDownloadLogs}
            disabled={logs.length === 0}
            title="Download logs"
          >
            <Download size={14} />
          </button>
          <button
            className={styles.iconButton}
            onClick={handleClearLogs}
            title="Clear logs"
          >
            <Trash2 size={14} />
          </button>
        </div>
      </div>

      {/* Phase progress (hidden for single-phase partial recon) */}
      {!hidePhaseProgress && (
        <div className={styles.phaseProgress}>
          {phases.map((phase, index) => {
            const phaseNum = index + 1
            const isActive = currentPhaseNumber === phaseNum
            const isCompleted = currentPhaseNumber !== null && phaseNum < currentPhaseNumber
            const isPending = currentPhaseNumber === null || phaseNum > currentPhaseNumber

            return (
              <div
                key={phase}
                className={`${styles.phaseItem} ${isActive ? styles.phaseActive : ''} ${isCompleted ? styles.phaseCompleted : ''} ${isPending ? styles.phasePending : ''}`}
                title={phase}
              >
                <span className={styles.phaseNumber}>{phaseNum}</span>
              </div>
            )
          })}
        </div>
      )}

      {/* Logs container */}
      <div
        ref={logsContainerRef}
        className={styles.logsContainer}
        onScroll={handleScroll}
      >
        {logs.length === 0 ? (
          <div className={styles.emptyLogs}>
            <Terminal size={24} />
            <p>Waiting for logs...</p>
          </div>
        ) : (
          <>
            {logs.map((log, index) => (
              <div
                key={index}
                className={`${styles.logLine} ${getLogClassName(log.level)}${
                  isTargetsLine(log.log) ? ` ${styles.logTargets}` : ''
                }${
                  isVulnerabilityLine(log.log) ? ` ${styles.logVulnerability}` : ''
                }`}
              >
                <span className={styles.logTimestamp}>
                  {new Date(log.timestamp).toLocaleTimeString()}
                </span>
                <span className={styles.logMessage}>{log.log}</span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </>
        )}
      </div>

      {/* Auto-scroll indicator */}
      {!autoScroll && (
        <button
          className={styles.scrollToBottom}
          onClick={() => {
            setAutoScroll(true)
            logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
          }}
        >
          Scroll to bottom
        </button>
      )}
    </div>
  )
}

export default ReconLogsDrawer

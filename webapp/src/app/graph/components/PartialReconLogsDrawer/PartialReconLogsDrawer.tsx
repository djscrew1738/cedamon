'use client'

import { useEffect, useRef, useState, useMemo, useCallback } from 'react'
import { X, Terminal, CheckCircle, AlertCircle, Square, Loader2, Trash2 } from 'lucide-react'
import { PARTIAL_RECON_PHASE_MAP } from '@/lib/recon-types'
import { WORKFLOW_TOOLS } from '@/components/projects/ProjectForm/WorkflowView/workflowDefinition'
import type { ReconLogEvent, ReconStatus, PartialReconState } from '@/lib/recon-types'
import drawerStyles from '@/app/graph/components/ReconLogsDrawer/ReconLogsDrawer.module.css'
import styles from './PartialReconLogsDrawer.module.css'

interface PartialReconLogsDrawerProps {
  isOpen: boolean
  onClose: () => void
  runs: PartialReconState[]
  logsMap: Record<string, ReconLogEvent[]>
  phaseMap: Record<string, { phase: string | null; phaseNumber: number | null }>
  activeRunId: string | null
  onSelectRun: (runId: string) => void
  onStop: (runId: string) => void
  onClearLogs: (runId: string) => void
  isConnected: boolean
}

function getToolLabel(toolId: string): string {
  const tool = WORKFLOW_TOOLS.find(t => t.id === toolId)
  return tool?.label || toolId || 'Unknown'
}

function getTabDotClass(status: string): string {
  switch (status) {
    case 'running':
    case 'starting':
    case 'stopping':
      return styles.tabDotRunning
    case 'completed':
      return styles.tabDotCompleted
    case 'error':
      return styles.tabDotError
    default:
      return styles.tabDotIdle
  }
}

/** Detects target-merge lines, same heuristic as ReconLogsDrawer. */
const isTargetsLine = (logText: string) =>
  logText.includes('[Targets]') &&
  (logText.includes('Merged ') || logText.includes('No targets'))

/** Detects vulnerability findings, same heuristic as ReconLogsDrawer. */
const isVulnerabilityLine = (logText: string) =>
  /\[\+\].*\b(?:vulns?|vulnerabilit(?:y|ies)|VULN|VULNERABLE|CVE-\d{4}-\d+)|VULN:|\b(?:CRITICAL|HIGH|MEDIUM|LOW):\s*\d+|\[(?:critical|high|medium|low)\]/i.test(
    logText
  )

function logLevelClass(level: string, text: string): string {
  if (isVulnerabilityLine(text)) return drawerStyles.logVulnerability
  if (isTargetsLine(text)) return drawerStyles.logTargets
  switch (level) {
    case 'warning': return drawerStyles.logWarning
    case 'error':   return drawerStyles.logError
    case 'success': return drawerStyles.logSuccess
    case 'action':  return drawerStyles.logAction
    default:        return drawerStyles.logInfo
  }
}

export function PartialReconLogsDrawer({
  isOpen,
  onClose,
  runs,
  logsMap,
  phaseMap,
  activeRunId,
  onSelectRun,
  onStop,
  onClearLogs,
  isConnected,
}: PartialReconLogsDrawerProps) {
  const logsEndRef = useRef<HTMLDivElement>(null)
  const logsContainerRef = useRef<HTMLDivElement>(null)
  const [autoScroll, setAutoScroll] = useState(true)

  // Determine active run — prefer activeRunId, fall back to first run
  const activeRun = useMemo(
    () => runs.find(r => r.run_id === activeRunId) || runs[0] || null,
    [runs, activeRunId]
  )

  const activeLogs = activeRun ? logsMap[activeRun.run_id] || [] : []
  const activePhaseData = activeRun ? phaseMap[activeRun.run_id] : undefined
  const activePhases = activeRun?.tool_id
    ? PARTIAL_RECON_PHASE_MAP[activeRun.tool_id] || ['Running']
    : ['Running']

  const status = (activeRun?.status || 'idle') as ReconStatus

  // Auto-scroll
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [activeLogs, autoScroll])

  const handleScroll = useCallback(() => {
    if (!logsContainerRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = logsContainerRef.current
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 50)
  }, [])

  // Handle tab close (stop run)
  const handleTabClose = useCallback((e: React.MouseEvent, runId: string) => {
    e.stopPropagation()
    onStop(runId)
  }, [onStop])

  // No runs state
  if (runs.length === 0) {
    return (
      <div className={`${drawerStyles.drawer} ${isOpen ? drawerStyles.drawerOpen : ''}`}>
        <div className={drawerStyles.header}>
          <div className={drawerStyles.titleContainer}>
            <Terminal size={14} />
            <span>Partial Reconnaissance Logs</span>
          </div>
          <button className={drawerStyles.closeButton} onClick={onClose} aria-label="Close drawer">
            <X size={14} />
          </button>
        </div>
        <div className={styles.noRuns}>
          <Terminal size={24} />
          <p>No partial recon runs yet</p>
        </div>
      </div>
    )
  }

  return (
    <div className={`${drawerStyles.drawer} ${isOpen ? drawerStyles.drawerOpen : ''}`}>
      {/* Header */}
      <div className={drawerStyles.header}>
        <div className={drawerStyles.titleContainer}>
          <Terminal size={14} />
          <span>Partial Reconnaissance Logs</span>
          <span className={`${drawerStyles.connectionBadge} ${isConnected ? drawerStyles.connectionConnected : drawerStyles.connectionDisconnected}`}>
            <span className={drawerStyles.connectionDot} />
            {isConnected ? 'Live' : 'Disconnected'}
          </span>
        </div>
        <button className={drawerStyles.closeButton} onClick={onClose} aria-label="Close drawer">
          <X size={14} />
        </button>
      </div>

      {/* Tab bar */}
      <div className={styles.tabBar} role="tablist">
        {runs.map(run => (
          <button
            key={run.run_id}
            role="tab"
            aria-selected={run.run_id === activeRunId}
            className={`${styles.tab} ${run.run_id === (activeRun?.run_id || runs[0]?.run_id) ? styles.tabActive : ''}`}
            onClick={() => onSelectRun(run.run_id)}
          >
            <span className={`${styles.tabDot} ${getTabDotClass(run.status)}`} />
            <span>{getToolLabel(run.tool_id)}</span>
            {run.status === 'running' || run.status === 'starting' ? (
              <Loader2 size={10} className={drawerStyles.spinner} />
            ) : null}
            {(run.status === 'completed' || run.status === 'error') && runs.length > 1 ? (
              <span
                className={styles.tabClose}
                onClick={(e) => handleTabClose(e, run.run_id)}
                title={`Stop ${getToolLabel(run.tool_id)}`}
              >
                <X size={10} />
              </span>
            ) : null}
          </button>
        ))}
      </div>

      {/* Status bar */}
      <div className={drawerStyles.statusBar}>
        <div className={drawerStyles.statusLeft}>
          {(status === 'running' || status === 'starting') && <span className={drawerStyles.runningIndicator} />}
          {status === 'completed' && <CheckCircle size={14} className={drawerStyles.successIcon} />}
          {status === 'error' && <AlertCircle size={14} className={drawerStyles.errorIcon} />}
          {status === 'stopping' && <Loader2 size={14} className={drawerStyles.spinner} />}
          {activeRun && (
            <span className={styles.statusTabName}>{getToolLabel(activeRun.tool_id)}</span>
          )}
          <span className={drawerStyles.statusText}>
            {status === 'idle' && 'Idle'}
            {status === 'running' && 'Running...'}
            {status === 'starting' && 'Starting...'}
            {status === 'stopping' && 'Stopping...'}
            {status === 'completed' && 'Completed'}
            {status === 'error' && `Error: ${activeRun?.error || 'Unknown error'}`}
          </span>
        </div>
        <div className={drawerStyles.statusActions}>
          <button
            className={drawerStyles.iconButton}
            onClick={() => activeRun && onClearLogs(activeRun.run_id)}
            title="Clear logs"
            aria-label="Clear logs"
          >
            <Trash2 size={12} />
          </button>
          {activeRun && (status === 'running' || status === 'starting') && (
            <button
              className={`${drawerStyles.iconButton} ${drawerStyles.iconButtonStop}`}
              onClick={() => onStop(activeRun.run_id)}
              title="Stop"
              aria-label="Stop"
            >
              <Square size={12} />
            </button>
          )}
        </div>
      </div>

      {/* Phase progress */}
      <div className={drawerStyles.phaseProgress}>
        {activePhases.map((phase, idx) => {
          const isActive = phase === activePhaseData?.phase && status === 'running'
          const isCompleted = activePhaseData?.phaseNumber != null && idx < activePhaseData.phaseNumber
          return (
            <div
              key={phase}
              className={`${drawerStyles.phaseItem} ${isActive ? drawerStyles.phaseActive : ''} ${isCompleted ? drawerStyles.phaseCompleted : ''} ${!isActive && !isCompleted ? drawerStyles.phasePending : ''}`}
              title={phase}
            >
              <span className={drawerStyles.phaseNumber}>
                {isCompleted ? '✓' : idx + 1}
              </span>
            </div>
          )
        })}
      </div>

      {/* Logs */}
      <div
        className={drawerStyles.logsContainer}
        ref={logsContainerRef}
        onScroll={handleScroll}
      >
        {activeLogs.length === 0 ? (
          <div className={drawerStyles.emptyLogs}>
            <Terminal size={20} />
            <p>Waiting for logs...</p>
          </div>
        ) : (
          activeLogs.map((log, idx) => (
            <div key={`${log.timestamp}-${idx}`} className={drawerStyles.logLine}>
              <span className={drawerStyles.logTimestamp}>{log.timestamp}</span>
              <span className={`${drawerStyles.logMessage} ${logLevelClass(log.level, log.log)}`}>
                {log.log}
              </span>
            </div>
          ))
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  )
}

export default PartialReconLogsDrawer

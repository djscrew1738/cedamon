'use client'

import React, { createContext, useContext } from 'react'
import type { ReconStatus, GvmStatus, GithubHuntStatus, TrufflehogStatus, PartialReconState } from '@/lib/recon-types'
import type { ActiveScan } from '@/app/graph/components/ScanProgressMonitor'

export interface GraphToolbarContextValue {
  projectId: string
  is3D: boolean
  showLabels: boolean
  onToggle3D: (value: boolean) => void
  onToggleLabels: (value: boolean) => void
  onToggleAI?: () => void
  isAIOpen?: boolean
  onOpenFileSystem?: () => void
  isFileSystemOpen?: boolean
  // Target info
  targetDomain?: string
  subdomainList?: string[]
  // Recon props
  onStartRecon?: () => void
  onPauseRecon?: () => void
  onResumeRecon?: () => void
  onStopRecon?: () => void
  onDownloadJSON?: () => void
  onToggleLogs?: () => void
  reconStatus?: ReconStatus
  hasReconData?: boolean
  isLogsOpen?: boolean
  // GVM props
  gvmAvailable?: boolean
  gvmReady?: boolean
  gvmReadinessMessage?: string
  onStartGvm?: () => void
  onPauseGvm?: () => void
  onResumeGvm?: () => void
  onStopGvm?: () => void
  onDownloadGvmJSON?: () => void
  onToggleGvmLogs?: () => void
  gvmStatus?: GvmStatus
  hasGvmData?: boolean
  isGvmLogsOpen?: boolean
  // GitHub Hunt props
  onStartGithubHunt?: () => void
  onPauseGithubHunt?: () => void
  onResumeGithubHunt?: () => void
  onStopGithubHunt?: () => void
  onDownloadGithubHuntJSON?: () => void
  onToggleGithubHuntLogs?: () => void
  githubHuntStatus?: GithubHuntStatus
  hasGithubHuntData?: boolean
  isGithubHuntLogsOpen?: boolean
  // TruffleHog props
  onStartTrufflehog?: () => void
  onPauseTrufflehog?: () => void
  onResumeTrufflehog?: () => void
  onStopTrufflehog?: () => void
  onDownloadTrufflehogJSON?: () => void
  onToggleTrufflehogLogs?: () => void
  trufflehogStatus?: TrufflehogStatus
  hasTrufflehogData?: boolean
  isTrufflehogLogsOpen?: boolean
  // Partial Recon props (multi-run)
  activePartialRecons?: PartialReconState[]
  activePartialReconLogsDrawer?: string | null
  onStopPartialRecon?: (runId: string) => void
  onTogglePartialReconLogs?: (runId: string) => void
  // Other Scans modal
  onToggleOtherScansModal?: () => void
  // Stealth mode
  stealthMode?: boolean
  // RoE
  roeEnabled?: boolean
  // Emergency Pause All
  onEmergencyPauseAll?: () => void
  isAnyPipelineRunning?: boolean
  isEmergencyPausing?: boolean
  // Live scan progress
  activeScans?: ActiveScan[]
  // Tunnel status
  tunnelStatus?: { ngrok?: { active: boolean; host?: string; port?: number }; chisel?: { active: boolean; host?: string; port?: number; srvPort?: number } }
  // Agent status
  agentActiveCount?: number
  agentConversations?: Array<{
    id: string
    title: string
    currentPhase: string
    iterationCount: number
    agentRunning: boolean
    sessionId: string
  }>
}

const GraphToolbarContext = createContext<GraphToolbarContextValue | null>(null)

export function GraphToolbarProvider({ children, value }: { children: React.ReactNode; value: GraphToolbarContextValue }) {
  return (
    <GraphToolbarContext.Provider value={value}>
      {children}
    </GraphToolbarContext.Provider>
  )
}

export function useGraphToolbar(): GraphToolbarContextValue {
  const ctx = useContext(GraphToolbarContext)
  if (!ctx) throw new Error('useGraphToolbar must be used within GraphToolbarProvider')
  return ctx
}

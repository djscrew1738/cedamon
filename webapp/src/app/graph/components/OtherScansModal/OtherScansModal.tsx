'use client'

import {
  Github,
  Search,
  Shield,
  AlertTriangle,
  Zap,
  Target,
  FileCode,
} from 'lucide-react'
import Link from 'next/link'
import { Modal } from '@/components/ui'
import type { GithubHuntStatus, TrufflehogStatus, GvmStatus, PartialReconState } from '@/lib/recon-types'
import { ScanCard } from './ScanCard'
import styles from './OtherScansModal.module.css'

interface OtherScansModalProps {
  isOpen: boolean
  onClose: () => void
  hasReconData: boolean
  hasGithubToken: boolean
  // GVM
  onStartGvm?: () => void
  onPauseGvm?: () => void
  onResumeGvm?: () => void
  onStopGvm?: () => void
  onDownloadGvmJSON?: () => void
  onToggleGvmLogs?: () => void
  gvmStatus?: GvmStatus
  gvmAvailable?: boolean
  hasGvmData?: boolean
  isGvmLogsOpen?: boolean
  // GitHub Hunt
  onStartGithubHunt?: () => void
  onPauseGithubHunt?: () => void
  onResumeGithubHunt?: () => void
  onStopGithubHunt?: () => void
  onDownloadGithubHuntJSON?: () => void
  onToggleGithubHuntLogs?: () => void
  githubHuntStatus?: GithubHuntStatus
  hasGithubHuntData?: boolean
  isGithubHuntLogsOpen?: boolean
  // TruffleHog
  onStartTrufflehog?: () => void
  onPauseTrufflehog?: () => void
  onResumeTrufflehog?: () => void
  onStopTrufflehog?: () => void
  onDownloadTrufflehogJSON?: () => void
  onToggleTrufflehogLogs?: () => void
  trufflehogStatus?: TrufflehogStatus
  hasTrufflehogData?: boolean
  isTrufflehogLogsOpen?: boolean
  // Partial recon scans (BadDns, Nuclei, SubdomainTakeover, JsRecon)
  partialReconRuns?: PartialReconState[]
  activePartialReconRunId?: string | null
  onStartPartialScan?: (toolId: string) => void
  onStopPartialScan?: (toolId: string) => void
  onTogglePartialScanLogs?: (toolId: string) => void
}

function TokenBanner() {
  return (
    <>
      <AlertTriangle size={14} style={{ color: '#f59e0b', flexShrink: 0 }} />
      <span>
        GitHub Access Token required.{' '}
        <Link href="/settings" style={{ color: 'var(--accent-primary)', fontWeight: 500 }}>
          Global Settings
        </Link>
      </span>
    </>
  )
}

function GvmUnavailableBanner() {
  return (
    <>
      <AlertTriangle size={14} style={{ color: '#f59e0b', flexShrink: 0 }} />
      <span>
        GVM is not installed. Run <code>./redamon.sh install --gvm</code> to enable vulnerability scanning.
      </span>
    </>
  )
}

function getRunForTool(runs: PartialReconState[], toolId: string): PartialReconState | undefined {
  return runs
    .filter(r => r.tool_id === toolId)
    .sort((a, b) => new Date(b.started_at || 0).getTime() - new Date(a.started_at || 0).getTime())[0]
}

export function OtherScansModal({
  isOpen,
  onClose,
  hasReconData,
  hasGithubToken,
  // GVM
  onStartGvm,
  onPauseGvm,
  onResumeGvm,
  onStopGvm,
  onDownloadGvmJSON,
  onToggleGvmLogs,
  gvmStatus = 'idle',
  gvmAvailable = true,
  hasGvmData = false,
  isGvmLogsOpen = false,
  // GitHub Hunt
  onStartGithubHunt,
  onPauseGithubHunt,
  onResumeGithubHunt,
  onStopGithubHunt,
  onDownloadGithubHuntJSON,
  onToggleGithubHuntLogs,
  githubHuntStatus = 'idle',
  hasGithubHuntData = false,
  isGithubHuntLogsOpen = false,
  // TruffleHog
  onStartTrufflehog,
  onPauseTrufflehog,
  onResumeTrufflehog,
  onStopTrufflehog,
  onDownloadTrufflehogJSON,
  onToggleTrufflehogLogs,
  trufflehogStatus = 'idle',
  hasTrufflehogData = false,
  isTrufflehogLogsOpen = false,
  // Partial recon
  partialReconRuns = [],
  activePartialReconRunId = null,
  onStartPartialScan,
  onStopPartialScan,
  onTogglePartialScanLogs,
}: OtherScansModalProps) {
  const partialStatus = (toolId: string) => getRunForTool(partialReconRuns, toolId)?.status || 'idle'
  const partialRunId = (toolId: string) => getRunForTool(partialReconRuns, toolId)?.run_id
  const isPartialLogsOpen = (toolId: string) => partialRunId(toolId) === activePartialReconRunId

  return (
    <Modal isOpen={isOpen} onClose={onClose} title="Other Scans" size="large">
      <div className={styles.content}>
        <ScanCard
          icon={<Shield size={18} className={styles.cardIcon} />}
          title="GVM Vulnerability Scan"
          description="Full vulnerability scan against discovered IPs and hostnames using the Greenbone Vulnerability Manager (GVM) stack."
          status={gvmStatus}
          isAvailable={gvmAvailable}
          unavailableMessage={<GvmUnavailableBanner />}
          requiresReconData
          hasReconData={hasReconData}
          onStart={onStartGvm ?? (() => {})}
          onPause={onPauseGvm}
          onResume={onResumeGvm}
          onStop={onStopGvm ?? (() => {})}
          onToggleLogs={onToggleGvmLogs}
          onDownload={onDownloadGvmJSON}
          isLogsOpen={isGvmLogsOpen}
          hasData={hasGvmData}
          startLabel="Start"
          busyLabel="Scanning..."
        />

        <ScanCard
          icon={<Github size={18} className={styles.cardIcon} />}
          title="GitHub Secret Hunt"
          description="Search GitHub repositories for exposed secrets, API keys, and credentials related to your target domain."
          status={githubHuntStatus}
          isAvailable={hasGithubToken}
          requiresGithubToken
          hasGithubToken={hasGithubToken}
          unavailableMessage={<TokenBanner />}
          onStart={onStartGithubHunt ?? (() => {})}
          onPause={onPauseGithubHunt}
          onResume={onResumeGithubHunt}
          onStop={onStopGithubHunt ?? (() => {})}
          onToggleLogs={onToggleGithubHuntLogs}
          onDownload={onDownloadGithubHuntJSON}
          isLogsOpen={isGithubHuntLogsOpen}
          hasData={hasGithubHuntData}
        />

        <ScanCard
          icon={<Search size={18} className={styles.cardIcon} />}
          title="TruffleHog Scanner"
          description="Deep secret scanning with 700+ detectors and optional verification against live APIs."
          status={trufflehogStatus}
          isAvailable={hasGithubToken}
          requiresGithubToken
          hasGithubToken={hasGithubToken}
          unavailableMessage={<TokenBanner />}
          onStart={onStartTrufflehog ?? (() => {})}
          onPause={onPauseTrufflehog}
          onResume={onResumeTrufflehog}
          onStop={onStopTrufflehog ?? (() => {})}
          onToggleLogs={onToggleTrufflehogLogs}
          onDownload={onDownloadTrufflehogJSON}
          isLogsOpen={isTrufflehogLogsOpen}
          hasData={hasTrufflehogData}
        />

        <ScanCard
          icon={<AlertTriangle size={18} className={styles.cardIcon} />}
          title="BadDNS Takeover Scan"
          description="Run the isolated BadDNS sidecar to detect dangling DNS records and subdomain takeover candidates."
          status={partialStatus('BadDns')}
          requiresReconData
          hasReconData={hasReconData}
          onStart={() => onStartPartialScan?.('BadDns')}
          onStop={() => onStopPartialScan?.('BadDns')}
          onToggleLogs={() => onTogglePartialScanLogs?.('BadDns')}
          isLogsOpen={isPartialLogsOpen('BadDns')}
          startLabel="Start"
          busyLabel="Running..."
        />

        <ScanCard
          icon={<Zap size={18} className={styles.cardIcon} />}
          title="Nuclei Targeted Scan"
          description="Run Nuclei vulnerability templates against live BaseURLs and endpoints discovered in the graph."
          status={partialStatus('Nuclei')}
          requiresReconData
          hasReconData={hasReconData}
          onStart={() => onStartPartialScan?.('Nuclei')}
          onStop={() => onStopPartialScan?.('Nuclei')}
          onToggleLogs={() => onTogglePartialScanLogs?.('Nuclei')}
          isLogsOpen={isPartialLogsOpen('Nuclei')}
          startLabel="Start"
          busyLabel="Running..."
        />

        <ScanCard
          icon={<Target size={18} className={styles.cardIcon} />}
          title="Subdomain Takeover Scan"
          description="Detect subdomain takeover opportunities using Subjack and Nuclei takeover templates against graph subdomains."
          status={partialStatus('SubdomainTakeover')}
          requiresReconData
          hasReconData={hasReconData}
          onStart={() => onStartPartialScan?.('SubdomainTakeover')}
          onStop={() => onStopPartialScan?.('SubdomainTakeover')}
          onToggleLogs={() => onTogglePartialScanLogs?.('SubdomainTakeover')}
          isLogsOpen={isPartialLogsOpen('SubdomainTakeover')}
          startLabel="Start"
          busyLabel="Running..."
        />

        <ScanCard
          icon={<FileCode size={18} className={styles.cardIcon} />}
          title="JS Recon / Secrets Scan"
          description="Analyze JavaScript files for endpoints, secrets, GraphQL references, and interesting hardcoded values."
          status={partialStatus('JsRecon')}
          requiresReconData
          hasReconData={hasReconData}
          onStart={() => onStartPartialScan?.('JsRecon')}
          onStop={() => onStopPartialScan?.('JsRecon')}
          onToggleLogs={() => onTogglePartialScanLogs?.('JsRecon')}
          isLogsOpen={isPartialLogsOpen('JsRecon')}
          startLabel="Start"
          busyLabel="Running..."
        />
      </div>
    </Modal>
  )
}

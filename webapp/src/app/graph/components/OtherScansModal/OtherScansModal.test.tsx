import { describe, test, expect, vi, afterEach } from 'vitest'
import { render, screen, fireEvent, cleanup } from '@testing-library/react'
import { OtherScansModal } from './OtherScansModal'

afterEach(() => {
  cleanup()
})

describe('OtherScansModal', () => {
  const baseProps = {
    isOpen: true,
    onClose: vi.fn(),
    hasReconData: true,
    hasGithubToken: true,
    gvmStatus: 'idle' as const,
    gvmAvailable: true,
    githubHuntStatus: 'idle' as const,
    trufflehogStatus: 'idle' as const,
    partialReconRuns: [],
    activePartialReconRunId: null,
    onStartPartialScan: vi.fn(),
    onStopPartialScan: vi.fn(),
    onTogglePartialScanLogs: vi.fn(),
  }

  test('renders all scan cards', () => {
    render(<OtherScansModal {...baseProps} />)
    expect(screen.getByText('GVM Vulnerability Scan')).toBeInTheDocument()
    expect(screen.getByText('GitHub Secret Hunt')).toBeInTheDocument()
    expect(screen.getByText('TruffleHog Scanner')).toBeInTheDocument()
    expect(screen.getByText('BadDNS Takeover Scan')).toBeInTheDocument()
    expect(screen.getByText('Nuclei Targeted Scan')).toBeInTheDocument()
    expect(screen.getByText('Subdomain Takeover Scan')).toBeInTheDocument()
    expect(screen.getByText('JS Recon / Secrets Scan')).toBeInTheDocument()
  })

  test('starts a partial recon scan with the correct tool id', () => {
    render(<OtherScansModal {...baseProps} />)
    fireEvent.click(screen.getByRole('button', { name: /start baddns takeover scan/i }))
    expect(baseProps.onStartPartialScan).toHaveBeenCalledWith('BadDns')

    fireEvent.click(screen.getByRole('button', { name: /start nuclei targeted scan/i }))
    expect(baseProps.onStartPartialScan).toHaveBeenCalledWith('Nuclei')

    fireEvent.click(screen.getByRole('button', { name: /start subdomain takeover scan/i }))
    expect(baseProps.onStartPartialScan).toHaveBeenCalledWith('SubdomainTakeover')

    fireEvent.click(screen.getByRole('button', { name: /start js recon/i }))
    expect(baseProps.onStartPartialScan).toHaveBeenCalledWith('JsRecon')
  })

  test('stops an active partial recon scan by tool id', () => {
    render(
      <OtherScansModal
        {...baseProps}
        partialReconRuns={[
          {
            project_id: 'p1',
            run_id: 'run-baddns',
            tool_id: 'BadDns',
            status: 'running',
            container_id: 'c1',
            started_at: new Date().toISOString(),
            completed_at: null,
            error: null,
            stats: null,
          },
        ]}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /stop baddns takeover scan/i }))
    expect(baseProps.onStopPartialScan).toHaveBeenCalledWith('BadDns')
  })

  test('toggles logs for an active partial recon scan by tool id', () => {
    render(
      <OtherScansModal
        {...baseProps}
        partialReconRuns={[
          {
            project_id: 'p1',
            run_id: 'run-nuclei',
            tool_id: 'Nuclei',
            status: 'running',
            container_id: 'c2',
            started_at: new Date().toISOString(),
            completed_at: null,
            error: null,
            stats: null,
          },
        ]}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /logs nuclei targeted scan/i }))
    expect(baseProps.onTogglePartialScanLogs).toHaveBeenCalledWith('Nuclei')
  })

  test('disables partial scans when recon data is missing', () => {
    render(<OtherScansModal {...baseProps} hasReconData={false} />)
    const baddnsStart = screen.getByRole('button', { name: /start baddns takeover scan/i })
    expect(baddnsStart).toBeDisabled()
  })

  test('disables GVM start and shows unavailable banner when GVM is not installed', () => {
    render(<OtherScansModal {...baseProps} gvmAvailable={false} />)
    const gvmStart = screen.getByRole('button', { name: /start gvm vulnerability scan/i })
    expect(gvmStart).toBeDisabled()
    expect(screen.getByText(/gvm is not installed/i)).toBeInTheDocument()
  })
})

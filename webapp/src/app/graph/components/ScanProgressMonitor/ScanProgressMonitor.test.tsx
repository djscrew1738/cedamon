import { render } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ScanProgressMonitor } from './ScanProgressMonitor'

describe('ScanProgressMonitor', () => {
  it('renders nothing when no scans are active', () => {
    const { container } = render(
      <ScanProgressMonitor scans={[{ label: 'Recon', status: 'idle' }]} />
    )
    expect(container.firstChild).toBeNull()
  })

  it('renders the first active scan with phase and progress', () => {
    const { container } = render(
      <ScanProgressMonitor
        scans={[
          { label: 'Recon', status: 'running', phase: 'Port Scanning', phaseNumber: 2, totalPhases: 6 },
          { label: 'GVM', status: 'running', phase: 'Scanning IPs', phaseNumber: 3, totalPhases: 4 },
        ]}
      />
    )

    expect(container.textContent).toContain('Recon')
    expect(container.textContent).toContain('Phase 2/6: Port Scanning')
    expect(container.textContent).toContain('+1')
  })

  it('caps phase progress between 1 and total phases', () => {
    const { container } = render(
      <ScanProgressMonitor
        scans={[
          { label: 'Recon', status: 'running', phase: 'Done', phaseNumber: 99, totalPhases: 4 },
        ]}
      />
    )

    expect(container.textContent).toContain('Phase 4/4: Done')
  })

  it('treats starting and paused scans as active', () => {
    const { container } = render(
      <ScanProgressMonitor
        scans={[
          { label: 'GVM', status: 'starting' },
          { label: 'GitHub Hunt', status: 'paused', phase: 'Scanning Repositories', phaseNumber: 2, totalPhases: 3 },
        ]}
      />
    )

    expect(container.textContent).toContain('GVM')
    expect(container.textContent).toContain('+1')
  })
})

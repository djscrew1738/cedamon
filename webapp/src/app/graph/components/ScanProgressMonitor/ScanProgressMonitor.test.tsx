import { render, fireEvent } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ScanProgressMonitor } from './ScanProgressMonitor'

describe('ScanProgressMonitor', () => {
  it('renders nothing when no scans are active', () => {
    const { container } = render(
      <ScanProgressMonitor scans={[{ label: 'Recon', status: 'idle' }]} />
    )
    expect(container.firstChild).toBeNull()
  })

  it('shows collapsed badge with scan count', () => {
    const { container } = render(
      <ScanProgressMonitor
        scans={[
          { label: 'Recon', status: 'running', phase: 'Port Scanning', phaseNumber: 2, totalPhases: 6 },
          { label: 'GVM', status: 'running', phase: 'Scanning IPs', phaseNumber: 3, totalPhases: 4 },
        ]}
      />
    )

    // Collapsed state — shows count, not individual scan details
    expect(container.textContent).toContain('2 scans active')
    expect(container.textContent).not.toContain('Recon')
    expect(container.textContent).not.toContain('GVM')
  })

  it('shows singular label for one scan', () => {
    const { container } = render(
      <ScanProgressMonitor
        scans={[
          { label: 'Recon', status: 'running', phase: 'Port Scanning', phaseNumber: 2, totalPhases: 6 },
        ]}
      />
    )

    expect(container.textContent).toContain('1 scan active')
  })

  it('expands to show all active scans on click', () => {
    const { container } = render(
      <ScanProgressMonitor
        scans={[
          { label: 'Recon', status: 'running', phase: 'Port Scanning', phaseNumber: 2, totalPhases: 6 },
          { label: 'GVM', status: 'running', phase: 'Scanning IPs', phaseNumber: 3, totalPhases: 4 },
        ]}
      />
    )

    // Click the trigger button (the only button inside this component's wrapper)
    const trigger = container.querySelector('button')!
    fireEvent.click(trigger)

    // Expanded state — shows all scan details
    expect(container.textContent).toContain('Recon')
    expect(container.textContent).toContain('Phase 2/6: Port Scanning')
    expect(container.textContent).toContain('GVM')
    expect(container.textContent).toContain('Phase 3/4: Scanning IPs')
  })

  it('caps phase progress between 1 and total phases', () => {
    const { container } = render(
      <ScanProgressMonitor
        scans={[
          { label: 'Recon', status: 'running', phase: 'Done', phaseNumber: 99, totalPhases: 4 },
        ]}
      />
    )

    fireEvent.click(container.querySelector('button')!)
    expect(container.textContent).toContain('Phase 4/4: Done')
  })

  it('treats starting and paused scans as active and shows paused tag', () => {
    const { container } = render(
      <ScanProgressMonitor
        scans={[
          { label: 'GVM', status: 'starting' },
          { label: 'GitHub Hunt', status: 'paused', phase: 'Scanning Repositories', phaseNumber: 2, totalPhases: 3 },
        ]}
      />
    )

    expect(container.textContent).toContain('2 scans active')

    fireEvent.click(container.querySelector('button')!)
    expect(container.textContent).toContain('GVM')
    expect(container.textContent).toContain('GitHub Hunt')
    expect(container.textContent).toContain('Paused')
  })

  it('shows elapsed time when provided', () => {
    const { container } = render(
      <ScanProgressMonitor
        scans={[
          { label: 'Recon', status: 'running', phase: 'Probing', phaseNumber: 1, totalPhases: 3, elapsed: '1m 23s' },
        ]}
      />
    )

    fireEvent.click(container.querySelector('button')!)
    expect(container.textContent).toContain('1m 23s')
  })
})

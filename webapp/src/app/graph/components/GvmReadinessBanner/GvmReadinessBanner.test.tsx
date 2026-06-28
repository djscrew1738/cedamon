import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { GvmReadinessBanner } from './GvmReadinessBanner'

describe('GvmReadinessBanner', () => {
  it('renders when GVM is available but not ready', () => {
    render(
      <GvmReadinessBanner
        available={true}
        ready={false}
        message="Feeds are still syncing."
      />
    )

    expect(screen.getByText('Feeds are still syncing.')).toBeInTheDocument()
  })

  it('renders default message when no message is provided', () => {
    render(<GvmReadinessBanner available={true} ready={false} />)

    expect(
      screen.getByText(/GVM feed sync in progress/i)
    ).toBeInTheDocument()
  })

  it('renders nothing when GVM is not available', () => {
    const { container } = render(<GvmReadinessBanner available={false} ready={false} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders nothing when GVM is ready', () => {
    const { container } = render(<GvmReadinessBanner available={true} ready={true} />)
    expect(container.firstChild).toBeNull()
  })
})

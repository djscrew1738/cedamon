'use client'

import { Component, type ReactNode, type ErrorInfo } from 'react'

interface ErrorBoundaryProps {
  /** The fallback UI to render when an error is caught */
  fallback?: ReactNode | ((error: Error, reset: () => void) => ReactNode)
  /** Optional child render function receives reset method */
  children: ReactNode
  /** Optional callback fired when an error is caught */
  onError?: (error: Error, errorInfo: ErrorInfo) => void
}

interface ErrorBoundaryState {
  hasError: boolean
  error: Error | null
}

/**
 * Catches rendering errors in its subtree and shows a fallback UI
 * instead of crashing the entire page. Wrap individual feature sections
 * (AttackPanel, AIAssistantDrawer, RedZoneTables, etc.) so a crash in
 * one doesn't take down the whole view.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('[ErrorBoundary]', error, errorInfo)
    this.props.onError?.(error, errorInfo)
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  render(): ReactNode {
    if (this.state.hasError && this.state.error) {
      if (typeof this.props.fallback === 'function') {
        return this.props.fallback(this.state.error, this.handleReset)
      }
      if (this.props.fallback) {
        return this.props.fallback
      }
      // Default fallback
      return (
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            justifyContent: 'center',
            padding: 'var(--space-8)',
            textAlign: 'center',
            minHeight: '200px',
          }}
        >
          <p style={{ color: 'var(--text-secondary)', marginBottom: 'var(--space-4)' }}>
            Something went wrong in this section.
          </p>
          <button
            onClick={this.handleReset}
            style={{
              background: 'var(--accent-primary)',
              color: 'var(--text-on-accent)',
              border: 'none',
              padding: 'var(--space-2) var(--space-4)',
              borderRadius: 'var(--radius-md)',
              cursor: 'pointer',
              fontSize: 'var(--text-sm)',
            }}
          >
            Retry
          </button>
        </div>
      )
    }

    return this.props.children
  }
}

/**
 * Smoke tests for GraphCanvas — verifies the three visual states render
 * without crashing: loading, error, and empty (no graph data).
 *
 * Run: npx vitest run src/app/graph/components/GraphCanvas/GraphCanvas.smoke.test.tsx
 */

import { describe, test, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { GraphCanvas } from './GraphCanvas'

describe('GraphCanvas smoke', () => {
  const baseProps = {
    projectId: 'test-p1',
    is3D: false,
    width: 800,
    height: 600,
    showLabels: true,
    selectedNode: null,
    onNodeClick: () => {},
    isDark: true,
  }

  test('renders loading state', () => {
    render(<GraphCanvas {...baseProps} data={undefined} isLoading={true} error={null} />)
    expect(screen.getByText(/Loading graph data/i)).toBeDefined()
  })

  test('renders error state', () => {
    render(
      <GraphCanvas
        {...baseProps}
        data={undefined}
        isLoading={false}
        error={new Error('API failure')}
      />,
    )
    expect(screen.getByText(/Error/i)).toBeDefined()
    expect(screen.getByText(/API failure/i)).toBeDefined()
  })

  test('renders empty state when no nodes', () => {
    render(
      <GraphCanvas
        {...baseProps}
        data={{ nodes: [], links: [], projectId: 'test-p1' }}
        isLoading={false}
        error={null}
      />,
    )
    expect(screen.getByText(/No graph data/i)).toBeDefined()
  })
})

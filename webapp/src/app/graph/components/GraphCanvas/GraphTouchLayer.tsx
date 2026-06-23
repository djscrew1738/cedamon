'use client'

import { ReactNode, useCallback } from 'react'
import { useGraphTouchGestures } from '../../hooks/useGraphTouchGestures'
import styles from './GraphCanvas.module.css'

interface GraphTouchLayerProps {
  /** React-force-graph instance ref. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  graphRef: React.RefObject<any>
  /** Whether the graph is in 3D mode. */
  is3D: boolean
  /** Canvas content. */
  children: ReactNode
}

const PAN_KEY_STEP = 10
const ZOOM_KEY_STEP = 0.1

/**
 * Wrapper that installs touch gesture handlers for the graph canvas
 * and keyboard navigation (arrow keys to pan, +/- to zoom).
 *
 * It sits behind the canvas in the DOM (same wrapper) so that node clicks and
 * other ForceGraph interactions are preserved for small taps. Once a gesture is
 * detected (pan or pinch) the handler calls preventDefault to stop the browser
 * from scrolling or zooming the page.
 */
export function GraphTouchLayer({ graphRef, is3D, children }: GraphTouchLayerProps) {
  // Custom touch gestures are used for 2D. 3D relies on the underlying
  // Three.js orbit controls, which already handle touch pan/rotate/zoom.
  const handlers = useGraphTouchGestures({ graphRef, is3D })

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const fg = graphRef.current
      if (!fg) return

      if (e.key === 'ArrowUp' || e.key === 'ArrowDown' || e.key === 'ArrowLeft' || e.key === 'ArrowRight') {
        e.preventDefault()
        if (is3D) {
          const camera = fg.camera()
          const controls = fg.controls()
          if (!camera) return
          const step = PAN_KEY_STEP * 2
          if (e.key === 'ArrowUp') { camera.position.y += step; controls?.target?.y !== undefined && (controls.target.y += step) }
          if (e.key === 'ArrowDown') { camera.position.y -= step; controls?.target?.y !== undefined && (controls.target.y -= step) }
          if (e.key === 'ArrowLeft') { camera.position.x -= step; controls?.target?.x !== undefined && (controls.target.x -= step) }
          if (e.key === 'ArrowRight') { camera.position.x += step; controls?.target?.x !== undefined && (controls.target.x += step) }
        } else {
          const center = fg.centerAt()
          if (center) {
            const dx = e.key === 'ArrowLeft' ? -PAN_KEY_STEP : e.key === 'ArrowRight' ? PAN_KEY_STEP : 0
            const dy = e.key === 'ArrowUp' ? -PAN_KEY_STEP : e.key === 'ArrowDown' ? PAN_KEY_STEP : 0
            fg.centerAt(center.x + dx, center.y + dy, 80)
          }
        }
        return
      }

      if (e.key === '+' || e.key === '=') {
        e.preventDefault()
        const z = fg.zoom()
        if (typeof z === 'number') fg.zoom(Math.min(z * (1 + ZOOM_KEY_STEP), 10), 200)
        return
      }
      if (e.key === '-') {
        e.preventDefault()
        const z = fg.zoom()
        if (typeof z === 'number') fg.zoom(Math.max(z * (1 - ZOOM_KEY_STEP), 0.05), 200)
        return
      }
    },
    [graphRef, is3D],
  )

  return (
    <div
      className={styles.wrapper}
      {...(is3D ? {} : handlers)}
      tabIndex={0}
      onKeyDown={handleKeyDown}
      aria-label="Graph canvas. Arrow keys to pan, +/- to zoom."
    >
      {children}
    </div>
  )
}

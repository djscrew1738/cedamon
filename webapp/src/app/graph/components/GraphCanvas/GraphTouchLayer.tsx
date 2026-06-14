'use client'

import { ReactNode } from 'react'
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

/**
 * Wrapper that installs touch gesture handlers for the graph canvas.
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

  return (
    <div className={styles.wrapper} {...(is3D ? {} : handlers)}>
      {children}
    </div>
  )
}

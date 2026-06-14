'use client'

import { useCallback, useRef } from 'react'

const TAP_THRESHOLD_PX = 8
const PINCH_ZOOM_DAMPING = 0.006
const PAN_DAMPING_3D = 0.35

interface TouchRecord {
  x: number
  y: number
}

interface GestureState {
  isPanning: boolean
  initialPinchDistance: number
  initialZoom: number
  initialCameraDistance: number
  initialCameraPosition: { x: number; y: number; z: number } | null
  initialTarget: { x: number; y: number; z: number } | null
}

interface UseGraphTouchGesturesOptions {
  /** Ref to the react-force-graph instance. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  graphRef: React.RefObject<any>
  /** Whether the graph is in 3D mode. */
  is3D: boolean
}

/**
 * Touch gesture handler for the graph canvas.
 *
 * Supports:
 * - Single-finger pan
 * - Two-finger pinch zoom
 *
 * Taps with movement below TAP_THRESHOLD_PX are ignored so that node clicks
 * can be handled by the underlying react-force-graph component.
 */
export function useGraphTouchGestures({ graphRef, is3D }: UseGraphTouchGesturesOptions) {
  const touchesRef = useRef<Map<number, TouchRecord>>(new Map())
  const gestureRef = useRef<GestureState>({
    isPanning: false,
    initialPinchDistance: 0,
    initialZoom: 1,
    initialCameraDistance: 0,
    initialCameraPosition: null,
    initialTarget: null,
  })

  const getDistance = (a: TouchRecord, b: TouchRecord): number => {
    const dx = a.x - b.x
    const dy = a.y - b.y
    return Math.sqrt(dx * dx + dy * dy)
  }

  const pan2D = useCallback((deltaX: number, deltaY: number) => {
    const fg = graphRef.current
    if (!fg) return
    const center = fg.centerAt?.()
    const zoom = fg.zoom?.()
    if (!center || typeof zoom !== 'number') return
    fg.centerAt(center.x - deltaX / zoom, center.y - deltaY / zoom)
  }, [graphRef])

  const zoom2D = useCallback((ratio: number) => {
    const fg = graphRef.current
    if (!fg) return
    const initialZoom = gestureRef.current.initialZoom
    fg.zoom?.(Math.max(0.01, initialZoom * ratio))
  }, [graphRef])

  const pan3D = useCallback((deltaX: number, deltaY: number) => {
    const fg = graphRef.current
    if (!fg) return
    const camera = fg.camera?.()
    const controls = fg.controls?.()
    if (!camera) return
    const offsetX = deltaX * PAN_DAMPING_3D
    const offsetY = -deltaY * PAN_DAMPING_3D
    camera.position.x += offsetX
    camera.position.y += offsetY
    if (controls?.target) {
      controls.target.x += offsetX
      controls.target.y += offsetY
    }
  }, [graphRef])

  const zoom3D = useCallback((ratio: number) => {
    const fg = graphRef.current
    if (!fg) return
    const camera = fg.camera?.()
    const controls = fg.controls?.()
    if (!camera) return
    const target = controls?.target || camera.position.clone()
    const direction = camera.position.clone().sub(target).normalize()
    const distance = gestureRef.current.initialCameraDistance / Math.max(ratio, 0.01)
    camera.position.copy(target).add(direction.multiplyScalar(distance))
  }, [graphRef])

  const onTouchStart = useCallback((e: React.TouchEvent) => {
    const touches = touchesRef.current
    for (let i = 0; i < e.changedTouches.length; i++) {
      const t = e.changedTouches[i]
      touches.set(t.identifier, { x: t.clientX, y: t.clientY })
    }

    const values = Array.from(touches.values())
    if (values.length === 2) {
      const fg = graphRef.current
      gestureRef.current.initialPinchDistance = getDistance(values[0], values[1])
      gestureRef.current.initialZoom = fg?.zoom?.() ?? 1
      const camera = fg?.camera?.()
      const controls = fg?.controls?.()
      if (camera) {
        gestureRef.current.initialCameraPosition = camera.position.clone()
        gestureRef.current.initialCameraDistance = camera.position.distanceTo(
          controls?.target || camera.position.clone()
        )
        gestureRef.current.initialTarget = controls?.target
          ? controls.target.clone()
          : camera.position.clone()
      }
    }
  }, [graphRef])

  const onTouchMove = useCallback((e: React.TouchEvent) => {
    const touches = touchesRef.current
    const valuesBefore = Array.from(touches.values())
    if (valuesBefore.length === 0) return

    // Update stored positions with current coordinates and compute deltas for changed touches.
    const deltas = new Map<number, { dx: number; dy: number }>()
    for (let i = 0; i < e.changedTouches.length; i++) {
      const t = e.changedTouches[i]
      const prev = touches.get(t.identifier)
      if (prev) {
        deltas.set(t.identifier, { dx: t.clientX - prev.x, dy: t.clientY - prev.y })
        touches.set(t.identifier, { x: t.clientX, y: t.clientY })
      }
    }

    const valuesAfter = Array.from(touches.values())

    if (valuesAfter.length === 1) {
      const delta = deltas.values().next().value as { dx: number; dy: number } | undefined
      if (!delta) return

      const totalDx = valuesAfter[0].x - valuesBefore[0].x
      const totalDy = valuesAfter[0].y - valuesBefore[0].y

      if (!gestureRef.current.isPanning) {
        if (Math.hypot(totalDx, totalDy) > TAP_THRESHOLD_PX) {
          gestureRef.current.isPanning = true
        } else {
          return
        }
      }

      e.preventDefault()
      if (is3D) {
        pan3D(delta.dx, delta.dy)
      } else {
        pan2D(delta.dx, delta.dy)
      }
    } else if (valuesAfter.length === 2) {
      e.preventDefault()
      const newDistance = getDistance(valuesAfter[0], valuesAfter[1])
      const ratio = newDistance / Math.max(gestureRef.current.initialPinchDistance, 1)
      if (is3D) {
        zoom3D(ratio)
      } else {
        zoom2D(ratio)
      }
    }
  }, [graphRef, is3D, pan2D, pan3D, zoom2D, zoom3D])

  const onTouchEnd = useCallback((e: React.TouchEvent) => {
    for (let i = 0; i < e.changedTouches.length; i++) {
      touchesRef.current.delete(e.changedTouches[i].identifier)
    }
    if (touchesRef.current.size === 0) {
      gestureRef.current.isPanning = false
      gestureRef.current.initialPinchDistance = 0
    }
  }, [])

  const onTouchCancel = useCallback(() => {
    touchesRef.current.clear()
    gestureRef.current.isPanning = false
    gestureRef.current.initialPinchDistance = 0
  }, [])

  return {
    onTouchStart,
    onTouchMove,
    onTouchEnd,
    onTouchCancel,
  }
}

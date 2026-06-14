import { describe, test, expect, vi } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useGraphTouchGestures } from './useGraphTouchGestures'

function createVec(x: number, y: number, z: number) {
  return {
    x,
    y,
    z,
    clone() {
      return createVec(this.x, this.y, this.z)
    },
    sub(v: { x: number; y: number; z: number }) {
      this.x -= v.x
      this.y -= v.y
      this.z -= v.z
      return this
    },
    normalize() {
      const len = Math.sqrt(this.x * this.x + this.y * this.y + this.z * this.z)
      if (len > 0) {
        this.x /= len
        this.y /= len
        this.z /= len
      }
      return this
    },
    multiplyScalar(n: number) {
      this.x *= n
      this.y *= n
      this.z *= n
      return this
    },
    copy(v: { x: number; y: number; z: number }) {
      this.x = v.x
      this.y = v.y
      this.z = v.z
      return this
    },
    add(v: { x: number; y: number; z: number }) {
      this.x += v.x
      this.y += v.y
      this.z += v.z
      return this
    },
    distanceTo(v: { x: number; y: number; z: number }) {
      const dx = this.x - v.x
      const dy = this.y - v.y
      const dz = this.z - v.z
      return Math.sqrt(dx * dx + dy * dy + dz * dz)
    },
  }
}

function createTouch(id: number, clientX: number, clientY: number) {
  return {
    identifier: id,
    clientX,
    clientY,
  } as unknown as Touch
}

function createTouchList(...touches: Touch[]) {
  return touches as unknown as TouchList
}

function createTouchEvent(type: string, touches: Touch[]) {
  return {
    type,
    changedTouches: createTouchList(...touches),
    touches: createTouchList(...touches),
    preventDefault: vi.fn(),
  } as unknown as React.TouchEvent
}

describe('useGraphTouchGestures', () => {
  test('small tap movement does not pan or zoom', () => {
    const centerAt = vi.fn()
    const zoom = vi.fn()
    const graphRef = { current: { centerAt, zoom } }

    const { result } = renderHook(() =>
      useGraphTouchGestures({ graphRef: graphRef as unknown as React.RefObject<unknown>, is3D: false }),
    )

    result.current.onTouchStart(createTouchEvent('touchstart', [createTouch(1, 100, 100)]))
    result.current.onTouchMove(createTouchEvent('touchmove', [createTouch(1, 103, 102)]))
    result.current.onTouchEnd(createTouchEvent('touchend', [createTouch(1, 103, 102)]))

    expect(centerAt).not.toHaveBeenCalled()
    expect(zoom).not.toHaveBeenCalled()
  })

  test('single-finger drag pans the 2D graph', () => {
    const centerAt = vi.fn().mockReturnValue({ x: 50, y: 50 })
    const zoom = vi.fn().mockReturnValue(2)
    const graphRef = { current: { centerAt, zoom } }

    const { result } = renderHook(() =>
      useGraphTouchGestures({ graphRef: graphRef as unknown as React.RefObject<unknown>, is3D: false }),
    )

    result.current.onTouchStart(createTouchEvent('touchstart', [createTouch(1, 100, 100)]))
    result.current.onTouchMove(createTouchEvent('touchmove', [createTouch(1, 130, 120)]))

    expect(centerAt).toHaveBeenCalledWith(50 - 30 / 2, 50 - 20 / 2)
  })

  test('two-finger pinch zooms the 2D graph', () => {
    const centerAt = vi.fn().mockReturnValue({ x: 0, y: 0 })
    const zoom = vi.fn().mockReturnValue(1)
    const graphRef = { current: { centerAt, zoom } }

    const { result } = renderHook(() =>
      useGraphTouchGestures({ graphRef: graphRef as unknown as React.RefObject<unknown>, is3D: false }),
    )

    result.current.onTouchStart(
      createTouchEvent('touchstart', [createTouch(1, 100, 100), createTouch(2, 200, 100)]),
    )
    result.current.onTouchMove(
      createTouchEvent('touchmove', [createTouch(1, 90, 100), createTouch(2, 210, 100)]),
    )

    // Initial distance = 100, new distance = 120 => ratio 1.2
    expect(zoom).toHaveBeenCalledWith(1.2)
  })

  test('single-finger drag pans the 3D camera', () => {
    const camera = { position: createVec(0, 0, 100) }
    const controls = { target: createVec(0, 0, 0) }
    const graphRef = { current: { camera: () => camera, controls: () => controls } }

    const { result } = renderHook(() =>
      useGraphTouchGestures({ graphRef: graphRef as unknown as React.RefObject<unknown>, is3D: true }),
    )

    result.current.onTouchStart(createTouchEvent('touchstart', [createTouch(1, 100, 100)]))
    result.current.onTouchMove(createTouchEvent('touchmove', [createTouch(1, 130, 120)]))

    expect(camera.position.x).toBeCloseTo(30 * 0.35)
    expect(camera.position.y).toBeCloseTo(-20 * 0.35)
    expect(controls.target.x).toBeCloseTo(30 * 0.35)
    expect(controls.target.y).toBeCloseTo(-20 * 0.35)
  })

  test('two-finger pinch zooms the 3D camera', () => {
    const camera = { position: createVec(0, 0, 100) }
    const controls = { target: createVec(0, 0, 0) }
    const graphRef = { current: { camera: () => camera, controls: () => controls } }

    const { result } = renderHook(() =>
      useGraphTouchGestures({ graphRef: graphRef as unknown as React.RefObject<unknown>, is3D: true }),
    )

    result.current.onTouchStart(
      createTouchEvent('touchstart', [createTouch(1, 100, 100), createTouch(2, 200, 100)]),
    )
    result.current.onTouchMove(
      createTouchEvent('touchmove', [createTouch(1, 90, 100), createTouch(2, 210, 100)]),
    )

    // Pinch ratio 1.2 => distance should shrink from 100 to 100/1.2
    expect(camera.position.z).toBeCloseTo(100 / 1.2)
  })

  test('touch cancellation resets gesture state', () => {
    const centerAt = vi.fn().mockReturnValue({ x: 0, y: 0 })
    const zoom = vi.fn().mockReturnValue(1)
    const graphRef = { current: { centerAt, zoom } }

    const { result } = renderHook(() =>
      useGraphTouchGestures({ graphRef: graphRef as unknown as React.RefObject<unknown>, is3D: false }),
    )

    result.current.onTouchStart(createTouchEvent('touchstart', [createTouch(1, 100, 100)]))
    result.current.onTouchCancel()
    result.current.onTouchMove(createTouchEvent('touchmove', [createTouch(1, 130, 120)]))

    expect(centerAt).not.toHaveBeenCalled()
  })
})

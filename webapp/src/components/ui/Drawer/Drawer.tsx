'use client'

import { ReactNode, useCallback, useEffect, useRef, useState } from 'react'
import styles from './Drawer.module.css'

const DRAG_CLOSE_THRESHOLD = 80
const DRAG_VELOCITY_THRESHOLD = 0.5

export interface DrawerProps {
  /** Whether the drawer is open */
  isOpen: boolean
  /** Callback when drawer should close */
  onClose: () => void
  /** Position of the drawer */
  position?: 'left' | 'right'
  /** Behavior mode: 'push' shrinks adjacent content, 'overlay' slides over content */
  mode?: 'push' | 'overlay'
  /** Width of the drawer (CSS value) */
  width?: string
  /** Title shown in drawer header */
  title?: ReactNode
  /** Optional action elements rendered in the header, immediately before the close button */
  headerActions?: ReactNode
  /** Content of the drawer */
  children: ReactNode
  /** Additional class name */
  className?: string
  /** Enable drag-to-resize handle on the inner edge */
  resizable?: boolean
  /** Minimum width in px when resizing */
  minWidth?: number
  /** Maximum width in px when resizing */
  maxWidth?: number
  /** Called with new width in px while the user drags the resize handle */
  onResize?: (widthPx: number) => void
  /** Called once when the user releases the resize handle (final width in px) */
  onResizeEnd?: (widthPx: number) => void
}

/** CSS selector for all focusable elements within the drawer */
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

export function Drawer({
  isOpen,
  onClose,
  position = 'left',
  mode = 'push',
  width = '300px',
  title,
  headerActions,
  children,
  className = '',
  resizable = false,
  minWidth = 240,
  maxWidth = 1200,
  onResize,
  onResizeEnd,
}: DrawerProps) {
  const positionClass = position === 'left' ? styles.drawerLeft : styles.drawerRight
  const modeClass = mode === 'overlay' ? styles.drawerOverlay : styles.drawerPush
  const drawerRef = useRef<HTMLDivElement | null>(null)
  const [isResizing, setIsResizing] = useState(false)
  const lastWidthRef = useRef<number | null>(null)

  const handleResizeStart = useCallback(
    (e: React.MouseEvent | React.TouchEvent) => {
      if (!resizable) return
      e.preventDefault()
      lastWidthRef.current = null
      setIsResizing(true)
    },
    [resizable],
  )

  useEffect(() => {
    if (!isResizing) return

    const computeWidth = (clientX: number) => {
      const el = drawerRef.current
      if (!el) return
      const rect = el.getBoundingClientRect()
      const raw = position === 'left' ? clientX - rect.left : rect.right - clientX
      const clamped = Math.min(Math.max(raw, minWidth), maxWidth)
      lastWidthRef.current = clamped
      onResize?.(clamped)
    }

    const handleMouseMove = (e: MouseEvent) => computeWidth(e.clientX)
    const handleTouchMove = (e: TouchEvent) => {
      if (e.touches.length > 0) computeWidth(e.touches[0].clientX)
    }

    const handleEnd = () => {
      setIsResizing(false)
      if (lastWidthRef.current != null) {
        onResizeEnd?.(lastWidthRef.current)
      }
    }

    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleEnd)
    document.addEventListener('touchmove', handleTouchMove, { passive: false })
    document.addEventListener('touchend', handleEnd)
    const prevUserSelect = document.body.style.userSelect
    const prevCursor = document.body.style.cursor
    document.body.style.userSelect = 'none'
    document.body.style.cursor = 'col-resize'

    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleEnd)
      document.removeEventListener('touchmove', handleTouchMove)
      document.removeEventListener('touchend', handleEnd)
      document.body.style.userSelect = prevUserSelect
      document.body.style.cursor = prevCursor
    }
  }, [isResizing, position, minWidth, maxWidth, onResize, onResizeEnd])

  const handleClass = position === 'left' ? styles.resizeHandleRight : styles.resizeHandleLeft

  // ── Touch drag-to-dismiss for overlay drawers ──
  const [dragOffset, setDragOffset] = useState(0)
  const [isDragging, setIsDragging] = useState(false)
  const dragStartXRef = useRef<number | null>(null)
  const dragStartTimeRef = useRef<number>(0)
  const pointerIdRef = useRef<number | null>(null)

  const dismissDirection = position === 'left' ? -1 : 1 // left drawer drags left (-), right drawer drags right (+)

  const handlePointerDown = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (mode !== 'overlay' || !isOpen) return
      // Only start drag from the drawer header or near the edge to avoid interfering with content scrolling
      const target = e.target as HTMLElement
      const isHeader = target.closest(`.${styles.drawerHeader}`) != null
      if (!isHeader) return
      dragStartXRef.current = e.clientX
      dragStartTimeRef.current = performance.now()
      pointerIdRef.current = e.pointerId
      setIsDragging(true)
      ;(e.currentTarget as HTMLDivElement).setPointerCapture(e.pointerId)
    },
    [mode, isOpen]
  )

  const handlePointerMove = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!isDragging || dragStartXRef.current == null || pointerIdRef.current !== e.pointerId) return
      const rawDelta = e.clientX - dragStartXRef.current
      const directedDelta = rawDelta * dismissDirection
      setDragOffset(directedDelta > 0 ? rawDelta : 0)
    },
    [isDragging, dismissDirection]
  )

  const handlePointerUp = useCallback(
    (e: React.PointerEvent<HTMLDivElement>) => {
      if (!isDragging || pointerIdRef.current !== e.pointerId) return
      const deltaTime = performance.now() - dragStartTimeRef.current
      const velocity = deltaTime > 0 ? Math.abs(dragOffset) / deltaTime : 0
      const shouldClose =
        (dragOffset * dismissDirection > DRAG_CLOSE_THRESHOLD) ||
        (dragOffset * dismissDirection > 0 && velocity > DRAG_VELOCITY_THRESHOLD)
      setIsDragging(false)
      setDragOffset(0)
      if (shouldClose) {
        onClose()
      }
      dragStartXRef.current = null
      pointerIdRef.current = null
    },
    [isDragging, dragOffset, dismissDirection, onClose]
  )

  const handlePointerCancel = useCallback(() => {
    setIsDragging(false)
    setDragOffset(0)
    dragStartXRef.current = null
    pointerIdRef.current = null
  }, [])

  // ── Focus management ──
  const previousActiveElement = useRef<HTMLElement | null>(null)

  // Trap focus within the drawer when open
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
        return
      }
      if (e.key !== 'Tab' || mode !== 'overlay') return
      const drawer = drawerRef.current
      if (!drawer) return
      const focusable = drawer.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
      if (focusable.length === 0) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      if (e.shiftKey) {
        if (document.activeElement === first) {
          e.preventDefault()
          last.focus()
        }
      } else {
        if (document.activeElement === last) {
          e.preventDefault()
          first.focus()
        }
      }
    },
    [mode, onClose],
  )

  useEffect(() => {
    if (!isOpen) return
    previousActiveElement.current = document.activeElement as HTMLElement
    // Focus the first focusable element inside the drawer
    requestAnimationFrame(() => {
      const drawer = drawerRef.current
      if (!drawer) return
      const focusable = drawer.querySelector<HTMLElement>(FOCUSABLE_SELECTOR)
      focusable?.focus()
    })
    return () => {
      previousActiveElement.current?.focus()
    }
  }, [isOpen])

  // ── Body scroll lock for overlay drawers ──
  useEffect(() => {
    if (mode !== 'overlay' || !isOpen) return
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = prev }
  }, [mode, isOpen])

  const transformStyle = isDragging && dragOffset !== 0
    ? ({ transform: `translateX(${dragOffset}px)` } as React.CSSProperties)
    : undefined

  return (
    <div
      ref={drawerRef}
      onPointerDown={handlePointerDown}
      onPointerMove={handlePointerMove}
      onPointerUp={handlePointerUp}
      onPointerCancel={handlePointerCancel}
      onKeyDown={handleKeyDown}
      role={mode === 'overlay' ? 'dialog' : undefined}
      aria-modal={mode === 'overlay' ? true : undefined}
      aria-label={typeof title === 'string' ? title : undefined}
      className={`${styles.drawer} ${positionClass} ${modeClass} ${isOpen ? styles.drawerOpen : ''} ${isResizing ? styles.drawerResizing : ''} ${isDragging ? styles.drawerDragging : ''} ${className}`}
      style={{ '--drawer-custom-width': width, ...transformStyle } as React.CSSProperties}
    >
      {title && (
        <div className={styles.drawerHeader}>
          <h2 className={styles.drawerTitle}>{title}</h2>
          {headerActions && (
            <div className={styles.drawerHeaderActions}>{headerActions}</div>
          )}
          <button
            className={styles.drawerClose}
            onClick={onClose}
            aria-label="Close drawer"
          >
            ×
          </button>
        </div>
      )}
      <div className={styles.drawerContent}>{children}</div>
      {resizable && isOpen && (
        <div
          className={`${styles.resizeHandle} ${handleClass} ${isResizing ? styles.resizeHandleActive : ''}`}
          onMouseDown={handleResizeStart}
          onTouchStart={handleResizeStart}
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize drawer"
        />
      )}
    </div>
  )
}

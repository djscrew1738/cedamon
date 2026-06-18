'use client'

import { useEffect, type RefObject } from 'react'

interface UseDrawerPositionOptions {
  /** Also track scroll events (useful inside scrollable containers) */
  trackScroll?: boolean
}

/**
 * Tracks the bounding rect of a container element and sets
 * `--drawer-top` / `--drawer-bottom` CSS custom properties on
 * `<html>` so that fixed-position overlay drawers pin correctly
 * inside scrolling containers.
 *
 * Usage:
 *   const bodyRef = useRef<HTMLDivElement>(null)
 *   useDrawerPosition(bodyRef, { trackScroll: true })
 */
export function useDrawerPosition(
  ref: RefObject<HTMLElement | null>,
  options: UseDrawerPositionOptions = {},
): void {
  const { trackScroll = false } = options

  useEffect(() => {
    const body = ref.current
    if (!body) return

    const update = () => {
      const rect = body.getBoundingClientRect()
      document.documentElement.style.setProperty('--drawer-top', `${rect.top}px`)
      document.documentElement.style.setProperty('--drawer-bottom', `${window.innerHeight - rect.bottom}px`)
    }

    update()
    const ro = new ResizeObserver(update)
    ro.observe(body)
    window.addEventListener('resize', update)

    if (trackScroll) {
      window.addEventListener('scroll', update, true)
    }

    return () => {
      ro.disconnect()
      window.removeEventListener('resize', update)
      if (trackScroll) {
        window.removeEventListener('scroll', update, true)
      }
    }
  }, [ref, trackScroll])
}

'use client'

import { useEffect, useRef } from 'react'

interface UsePollingOptions {
  /** Interval in milliseconds (default 5 000). */
  interval?: number
  /** When true, pauses polling (default false). */
  disabled?: boolean
}

/**
 * Calls `callback` on an interval.
 * The interval resets when `deps` change so the callback always sees fresh
 * closure values without stale captures.
 *
 * @example
 * ```ts
 * usePolling(() => fetch('/api/status'), { interval: 5000 })
 * ```
 */
export function usePolling(
  callback: () => void,
  options: UsePollingOptions & { deps?: unknown[] } = {},
): void {
  const { interval = 5000, disabled = false, deps = [] } = options
  const savedCallback = useRef(callback)

  // Keep the ref in sync so the interval always calls the latest version
  useEffect(() => {
    savedCallback.current = callback
  })

  useEffect(() => {
    if (disabled) return

    savedCallback.current()

    const id = setInterval(() => savedCallback.current(), interval)
    return () => clearInterval(id)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [interval, disabled, ...deps])
}

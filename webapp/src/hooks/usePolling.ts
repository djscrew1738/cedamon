'use client'

import { useEffect, useRef } from 'react'

interface UsePollingOptions {
  /** Interval in milliseconds (default 5 000). */
  interval?: number
  /** When true, pauses polling (default false). */
  disabled?: boolean
  /** Max random jitter in ms added to the first call (spreads burst-starts). Default 2000. */
  jitter?: number
}

/**
 * Calls `callback` on an interval.
 * The interval resets when `deps` change so the callback always sees fresh
 * closure values without stale captures.
 *
 * Jitter adds a random delay to the initial call so multiple instances started
 * at the same time don't all fire their first request against the backend
 * simultaneously.
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
  const { interval = 5000, disabled = false, jitter = 2000, deps = [] } = options
  const savedCallback = useRef(callback)

  // Keep the ref in sync so the interval always calls the latest version
  useEffect(() => {
    savedCallback.current = callback
  })

  useEffect(() => {
    if (disabled) return

    let timeoutId: ReturnType<typeof setTimeout> | undefined
    let intervalId: ReturnType<typeof setInterval> | undefined

    const startInterval = () => {
      savedCallback.current()
      intervalId = setInterval(() => savedCallback.current(), interval)
    }

    // Apply jitter: random delay before the first call
    if (jitter > 0) {
      const delay = Math.floor(Math.random() * jitter)
      timeoutId = setTimeout(startInterval, delay)
    } else {
      startInterval()
    }

    return () => {
      if (timeoutId) clearTimeout(timeoutId)
      if (intervalId) clearInterval(intervalId)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [interval, disabled, ...deps])
}

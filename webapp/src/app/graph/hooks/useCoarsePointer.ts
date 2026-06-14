'use client'

import { useEffect, useState } from 'react'

/**
 * Returns true when the primary pointer is coarse (touch), e.g. phones and
 * tablets. Returns false for mouse-driven desktops.
 */
export function useCoarsePointer(): boolean {
  const [isCoarse, setIsCoarse] = useState(false)

  useEffect(() => {
    if (typeof window === 'undefined') return
    const mq = window.matchMedia('(pointer: coarse)')
    setIsCoarse(mq.matches)
    const handler = (e: MediaQueryListEvent) => setIsCoarse(e.matches)
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])

  return isCoarse
}

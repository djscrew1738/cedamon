'use client'

import { useEffect, useRef, type RefObject } from 'react'

/**
 * Calls `handler` when a pointer-down event occurs outside `ref`.
 * Useful for closing dropdowns, menus, and modals.
 */
export function useClickOutside<T extends HTMLElement>(
  handler: () => void,
): RefObject<T | null> {
  const ref = useRef<T | null>(null)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (ref.current && !ref.current.contains(event.target as Node)) {
        handler()
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [handler])

  return ref
}

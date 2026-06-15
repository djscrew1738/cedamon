'use client';

import { useEffect, useState } from 'react';

/**
 * Reactively queries a CSS media query string and returns whether it matches.
 *
 * Usage:
 *   const isSmall = useMediaQuery('(max-width: 768px)');
 *   const isDark = useMediaQuery('(prefers-color-scheme: dark)');
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => {
    if (typeof window !== 'undefined') {
      return window.matchMedia(query).matches;
    }
    return false;
  });

  useEffect(() => {
    const mql = window.matchMedia(query);
    const handler = (e: MediaQueryListEvent) => setMatches(e.matches);
    mql.addEventListener('change', handler);
    return () => mql.removeEventListener('change', handler);
  }, [query]);

  return matches;
}

/**
 * Convenience hook: true when the viewport is ≤ 768px (tablet / mobile).
 */
export function useIsMobile(): boolean {
  return useMediaQuery('(max-width: 768px)');
}

/**
 * Convenience hook: true when the viewport is ≤ 480px (small phone).
 */
export function useIsSmallPhone(): boolean {
  return useMediaQuery('(max-width: 480px)');
}

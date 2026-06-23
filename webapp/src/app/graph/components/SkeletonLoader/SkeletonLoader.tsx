'use client'

import styles from './SkeletonLoader.module.css'

type SkeletonVariant = 'text' | 'avatar' | 'card' | 'row'
type SkeletonSize = 'sm' | 'md' | 'lg'

interface SkeletonLoaderProps {
  /**
   * Visual variant:
   * - `text`: short inline bar (60% width, default)
   * - `avatar`: circular placeholder
   * - `card`: large rectangular block
   * - `row`: full-width bar
   */
  variant?: SkeletonVariant
  /** Size preset affecting height. */
  size?: SkeletonSize
  /** Optional inline style override. */
  style?: React.CSSProperties
}

/**
 * Pulsing skeleton placeholder for async-loaded content.
 *
 * Usage:
 * ```tsx
 * <SkeletonLoader variant="card" />
 * <SkeletonLoader variant="text" size="sm" />
 * ```
 */
export function SkeletonLoader({
  variant = 'text',
  size = 'md',
  style,
}: SkeletonLoaderProps) {
  return (
    <div
      className={`${styles.skeleton} ${styles[size]} ${styles[variant]}`}
      style={style}
      aria-hidden="true"
    />
  )
}

/**
 * Renders a list of skeleton rows, useful for data table / list loading states.
 */
export function SkeletonLoaderList({
  count = 5,
  variant = 'row',
  size = 'md',
}: {
  count?: number
  variant?: SkeletonVariant
  size?: SkeletonSize
}) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: 16 }}>
      {Array.from({ length: count }, (_, i) => (
        <SkeletonLoader key={i} variant={variant} size={size} />
      ))}
    </div>
  )
}

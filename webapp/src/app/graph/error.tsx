'use client'

import { useEffect } from 'react'
import styles from './error.module.css'

const isChunkLoadError = (error: Error) =>
  error.name === 'ChunkLoadError' ||
  /Loading chunk [\w/.-]+ failed/i.test(error.message) ||
  /Failed to load chunk/i.test(error.message)

export default function GraphError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    if (isChunkLoadError(error)) {
      window.location.reload()
      return
    }
    console.error('Graph route error:', error)
  }, [error])

  if (isChunkLoadError(error)) {
    return null
  }

  return (
    <div className={styles.container}>
      <h2 className={styles.heading}>
        Failed to load graph view
      </h2>
      <p className={styles.message}>
        {error.message || 'An unexpected error occurred while rendering the graph.'}
      </p>
      <button
        type="button"
        onClick={reset}
        className={styles.retryButton}
      >
        Retry
      </button>
    </div>
  )
}

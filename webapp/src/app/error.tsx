'use client'

import { useEffect } from 'react'
import styles from './error.module.css'

const isChunkLoadError = (error: Error) =>
  error.name === 'ChunkLoadError' ||
  /Loading chunk [\w/.-]+ failed/i.test(error.message) ||
  /Failed to load chunk/i.test(error.message)

export default function Error({
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
    console.error('App error boundary:', error)
  }, [error])

  if (isChunkLoadError(error)) {
    return null
  }

  return (
    <div className={styles.container}>
      <h2 className={styles.heading}>
        Something went wrong
      </h2>
      <p className={styles.message}>
        {error.message || 'An unexpected error occurred.'}
      </p>
      <button
        type="button"
        onClick={reset}
        className={styles.retryButton}
      >
        Try again
      </button>
    </div>
  )
}

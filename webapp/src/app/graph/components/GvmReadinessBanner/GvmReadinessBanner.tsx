'use client'

import { useState } from 'react'
import { ShieldAlert, X } from 'lucide-react'
import styles from './GvmReadinessBanner.module.css'

interface GvmReadinessBannerProps {
  available?: boolean
  ready?: boolean
  message?: string
}

export function GvmReadinessBanner({ available, ready, message }: GvmReadinessBannerProps) {
  const [dismissed, setDismissed] = useState(false)

  if (!available || ready || dismissed) return null

  return (
    <div className={styles.banner} role="status" aria-live="polite">
      <ShieldAlert size={14} className={styles.icon} />
      <span className={styles.text}>
        {message || 'GVM feed sync in progress — scans will start when ready'}
      </span>
      <button
        className={styles.dismissButton}
        onClick={() => setDismissed(true)}
        aria-label="Dismiss banner"
      >
        <X size={14} />
      </button>
    </div>
  )
}

export default GvmReadinessBanner

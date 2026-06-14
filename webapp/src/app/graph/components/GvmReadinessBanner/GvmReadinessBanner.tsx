'use client'

import { ShieldAlert } from 'lucide-react'
import styles from './GvmReadinessBanner.module.css'

interface GvmReadinessBannerProps {
  available?: boolean
  ready?: boolean
  message?: string
}

export function GvmReadinessBanner({ available, ready, message }: GvmReadinessBannerProps) {
  if (!available || ready) return null

  return (
    <div className={styles.banner} role="status" aria-live="polite">
      <ShieldAlert size={14} className={styles.icon} />
      <span className={styles.text}>
        {message || 'GVM is installed but still syncing vulnerability feeds. Scans will be disabled until sync completes.'}
      </span>
    </div>
  )
}

export default GvmReadinessBanner

'use client'

import styles from './AttackPanel.module.css'

interface AttackSurfaceSummaryCardProps {
  icon: React.ReactNode
  label: string
  value: string
  delta?: string
}

export function AttackSurfaceSummaryCard({ icon, label, value, delta }: AttackSurfaceSummaryCardProps) {
  return (
    <div className={styles.summaryCard}>
      <div className={styles.summaryIcon}>{icon}</div>
      <div className={styles.summaryValueRow}>
        <span className={styles.summaryValue}>{value}</span>
        {delta ? <span className={styles.deltaBadge}>+{delta}</span> : null}
      </div>
      <div className={styles.summaryLabel}>{label}</div>
    </div>
  )
}

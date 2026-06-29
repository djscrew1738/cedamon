'use client'

import { SCAN_PROFILES, DEFAULT_PROFILE, type ScanProfile } from './scanProfiles'
import styles from './ScanProfileSelector.module.css'

interface ScanProfileSelectorProps {
  selected: string
  onChange: (profile: ScanProfile) => void
  disabled?: boolean
}

export function ScanProfileSelector({ selected, onChange, disabled }: ScanProfileSelectorProps) {
  return (
    <div className={styles.wrapper}>
      <div className={styles.label}>Scan Profile</div>
      <div className={styles.grid}>
        {SCAN_PROFILES.map(profile => {
          const isActive = selected === profile.id
          const isDefault = profile.id === DEFAULT_PROFILE
          return (
            <button
              key={profile.id}
              type="button"
              className={`${styles.card} ${isActive ? styles.cardActive : ''}`}
              onClick={() => onChange(profile)}
              disabled={disabled}
              title={profile.description}
            >
              <span className={styles.icon}>{profile.icon}</span>
              <span className={styles.name}>
                {profile.name}
                {isDefault && <span className={styles.recommended}>Recommended</span>}
              </span>
              <span className={styles.desc}>{profile.description}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}

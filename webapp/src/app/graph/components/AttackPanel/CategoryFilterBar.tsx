'use client'

import styles from './AttackPanel.module.css'

interface CategoryConfig {
  label: string
  icon: React.ReactNode
  color: string
}

interface CategoryFilterBarProps {
  categories: Record<string, CategoryConfig>
  activeCategory: string | null
  categoryCounts: Record<string, number>
  onCategoryChange: (category: string | null) => void
}

export function CategoryFilterBar({
  categories,
  activeCategory,
  categoryCounts,
  onCategoryChange,
}: CategoryFilterBarProps) {
  return (
    <div className={styles.filters}>
      <button
        className={`${styles.filterPill} ${activeCategory === null ? styles.filterPillActive : ''}`}
        onClick={() => onCategoryChange(null)}
        aria-pressed={activeCategory === null}
      >
        All
      </button>
      {Object.entries(categories).map(([key, cfg]) => (
        <button
          key={key}
          className={`${styles.filterPill} ${activeCategory === key ? styles.filterPillActive : ''}`}
          onClick={() => onCategoryChange(key)}
          aria-pressed={activeCategory === key}
        >
          {cfg.icon}
          <span>{cfg.label}</span>
          {categoryCounts[key] && (
            <span className={styles.filterCount}>{categoryCounts[key]}</span>
          )}
        </button>
      ))}
    </div>
  )
}

'use client'

import { Globe, Calendar, Settings, Trash2, Play, ExternalLink } from 'lucide-react'
import Link from 'next/link'
import styles from './ProjectCard.module.css'

interface ProjectCardProps {
  id: string
  name: string
  targetDomain: string
  description?: string | null
  createdAt: string
  isSelected?: boolean
  onSelect?: () => void
  onDelete?: () => void
  onStartScan?: () => void
}

export function ProjectCard({
  id,
  name,
  targetDomain,
  description,
  createdAt,
  isSelected,
  onSelect,
  onDelete,
  onStartScan,
}: ProjectCardProps) {
  const formattedDate = new Date(createdAt).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric'
  })

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      onSelect?.()
    }
  }

  return (
    <div
      className={`card cardClickable ${isSelected ? 'cardSelected' : ''} ${styles.projectCard}`}
      onClick={onSelect}
      role={onSelect ? 'button' : undefined}
      tabIndex={onSelect ? 0 : undefined}
      onKeyDown={onSelect ? handleKeyDown : undefined}
    >
      <div className="cardHeader">
        <div>
          <h3 className="cardTitle">{name}</h3>
          {description && <p className="cardSubtitle">{description}</p>}
        </div>
        <div className={styles.actions}>
          <Link
            href={`/projects/${id}/settings`}
            className="iconButton"
            onClick={(e) => e.stopPropagation()}
            title="Project Settings"
          >
            <Settings size={14} />
          </Link>
          {onDelete && (
            <button
              className="iconButton"
              onClick={(e) => {
                e.stopPropagation()
                onDelete()
              }}
              title="Delete Project"
            >
              <Trash2 size={14} />
            </button>
          )}
        </div>
      </div>
      <div className="cardBody">
        <div className={styles.meta}>
          <div className={styles.metaItem}>
            <Globe size={12} />
            <span>{targetDomain || 'No target set'}</span>
          </div>
          <div className={styles.metaItem}>
            <Calendar size={12} />
            <span>{formattedDate}</span>
          </div>
        </div>
      </div>
      {(onStartScan || onSelect) && (
        <div className={styles.footerActions}>
          {onStartScan && (
            <button
              className={styles.scanButton}
              onClick={(e) => {
                e.stopPropagation()
                onStartScan()
              }}
              title="Start reconnaissance pipeline"
            >
              <Play size={12} />
              Start Scan
            </button>
          )}
          {onSelect && (
            <Link
              href={`/graph?project=${id}`}
              className={styles.graphLink}
              onClick={(e) => e.stopPropagation()}
              title="Open in attack graph"
            >
              <ExternalLink size={12} />
              View Graph
            </Link>
          )}
        </div>
      )}
    </div>
  )
}

export default ProjectCard

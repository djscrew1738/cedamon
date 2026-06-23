'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import Image from 'next/image'
import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { Crosshair, FolderOpen, Shield, BookOpen, TrendingUp, FileText, Settings, Users, GitBranch, Menu, X } from 'lucide-react'
import { ThemeToggle } from '@/components/ThemeToggle'
import { ProjectSelector } from './ProjectSelector'
import { UserSelector } from './UserSelector'
import { useAuth } from '@/providers/AuthProvider'
import { useProject } from '@/providers/ProjectProvider'
import styles from './GlobalHeader.module.css'

interface PipelineStatus {
  recon?: { status: string }
  gvm?: { status: string }
  githubHunt?: { status: string }
}

const SWIPE_CLOSE_THRESHOLD = 40

const STATUS_COLORS: Record<string, string> = {
  running: '#22c55e',
  starting: '#eab308',
  paused: '#f97316',
  error: '#ef4444',
  stopping: '#ef4444',
  completed: '#22c55e',
}

const STATUS_LABELS: Record<string, string> = {
  running: 'Running',
  starting: 'Starting',
  paused: 'Paused',
  error: 'Error',
  stopping: 'Stopping',
}

function getStatusColor(status: string): string {
  return STATUS_COLORS[status] || '#6b7280'
}

function getStatusLabel(pipeline: string, status: string): string {
  const label = STATUS_LABELS[status] || status.charAt(0).toUpperCase() + status.slice(1)
  const names: Record<string, string> = {
    recon: 'Recon',
    gvm: 'GVM Scan',
    githubHunt: 'GitHub Hunt',
  }
  return `${names[pipeline] || pipeline}: ${label}`
}

export function GlobalHeader({ reconStatus: reconStatusProp, gvmStatus: gvmStatusProp }: { reconStatus?: string; gvmStatus?: string } = {}) {
  const pathname = usePathname()
  const { isAdmin } = useAuth()
  const { projectId } = useProject()
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const touchStartXRef = useRef<number | null>(null)
  const [pipelineStatus, setPipelineStatus] = useState<PipelineStatus | null>(null)

  // Close mobile menu on route change
  useEffect(() => {
    setMobileMenuOpen(false)
  }, [pathname])

  // Prevent body scroll when mobile menu is open
  useEffect(() => {
    if (mobileMenuOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = ''
    }
    return () => { document.body.style.overflow = '' }
  }, [mobileMenuOpen])

  // Poll pipeline status when projectId is available and no prop overrides given
  useEffect(() => {
    if (!projectId || reconStatusProp || gvmStatusProp) return
    let cancelled = false
    const fetchStatus = async () => {
      try {
        const res = await fetch(`/api/analytics/pipeline-status?projectId=${projectId}`)
        if (res.ok && !cancelled) setPipelineStatus(await res.json())
      } catch { /* ignore */ }
    }
    fetchStatus()
    const interval = setInterval(fetchStatus, 10000)
    return () => { cancelled = true; clearInterval(interval) }
  }, [projectId, reconStatusProp, gvmStatusProp])

  // Resolve effective status for each pipeline (prop override > polled data)
  const effectiveReconStatus = reconStatusProp || pipelineStatus?.recon?.status
  const effectiveGvmStatus = gvmStatusProp || pipelineStatus?.gvm?.status
  const effectiveGithubHuntStatus = pipelineStatus?.githubHunt?.status

  const activePipelines = [
    { key: 'recon', status: effectiveReconStatus },
    { key: 'gvm', status: effectiveGvmStatus },
    { key: 'githubHunt', status: effectiveGithubHuntStatus },
  ].filter((p): p is { key: string; status: string } =>
    !!p.status && !['idle', 'completed'].includes(p.status)
  )

  const coreNav = [
    { label: 'Red Zone', href: '/graph', icon: <Crosshair size={16} /> },
    ...(projectId
      ? [{ label: 'Recon Pipeline', href: `/projects/${projectId}/settings`, icon: <GitBranch size={16} /> }]
      : []),
    { label: 'CypherFix', href: '/cypherfix', icon: <Shield size={16} /> },
    { label: 'Insights', href: '/insights', icon: <TrendingUp size={16} /> },
    { label: 'Reports', href: '/reports', icon: <FileText size={16} /> },
  ]

  const utilityLinks = [
    { label: 'Projects', href: '/projects', icon: <FolderOpen size={16} /> },
    ...(isAdmin ? [{ label: 'Users', href: '/settings/users', icon: <Users size={16} /> }] : []),
    { label: 'Settings', href: '/settings', icon: <Settings size={16} /> },
  ]

  const handleNavClick = useCallback(() => {
    setMobileMenuOpen(false)
  }, [])

  return (
    <header className={styles.header}>
      <Link href="/graph" className={styles.logo} onClick={handleNavClick}>
        <Image src="/logo.png" alt="RedAmon" width={28} height={28} className={styles.logoImg} />
        <span className={styles.logoText}>
          <span className={styles.logoAccent}>Red</span>Amon
        </span>
      </Link>

      <div className={styles.spacer} />

      {/* Pipeline status pills */}
      {activePipelines.length > 0 && (
        <div className={styles.pipelinePills}>
          {activePipelines.map(p => (
            <Link
              key={p.key}
              href="/graph"
              className={styles.pipelinePill}
              title={getStatusLabel(p.key, p.status)}
            >
              <span className={styles.pipelineDot} style={{ backgroundColor: getStatusColor(p.status) }} />
              <span>{getStatusLabel(p.key, p.status)}</span>
            </Link>
          ))}
        </div>
      )}

      {/* Desktop navigation */}
      <div className={styles.actions}>
        <nav className={styles.coreNav}>
          {coreNav.map(item => {
            const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`)
            return (
              <Link
                key={item.href}
                href={item.href}
                className={`${styles.coreNavItem} ${isActive ? styles.coreNavItemActive : ''}`}
              >
                {item.icon}
                <span>{item.label}</span>
              </Link>
            )
          })}
        </nav>

        <Link
          href="/projects"
          className={`${styles.navItem} ${pathname === '/projects' || pathname.startsWith('/projects/') ? styles.navItemActive : ''}`}
        >
          <FolderOpen size={14} />
          <span>Projects</span>
        </Link>

        {isAdmin && (
          <Link
            href="/settings/users"
            className={`${styles.navItem} ${pathname === '/settings/users' ? styles.navItemActive : ''}`}
          >
            <Users size={14} />
            <span>Users</span>
          </Link>
        )}

        <div className={styles.divider} />

        <ProjectSelector />

        <div className={styles.divider} />

        <ThemeToggle />

        <div className={styles.divider} />

        <a
          href="https://github.com/samugit83/redamon/wiki"
          target="_blank"
          rel="noopener noreferrer"
          className={styles.helpLink}
          title="Wiki Documentation"
        >
          <BookOpen size={17} />
        </a>

        <div className={styles.divider} />

        <UserSelector />

        <div className={styles.divider} />

        <Link
          href="/settings"
          className={`${styles.helpLink} ${pathname === '/settings' ? styles.navItemActive : ''}`}
          title="Global Settings"
        >
          <Settings size={17} />
        </Link>
      </div>

      {/* Mobile hamburger button */}
      <button
        className={styles.hamburger}
        onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
        aria-label={mobileMenuOpen ? 'Close menu' : 'Open menu'}
        aria-expanded={mobileMenuOpen}
      >
        {mobileMenuOpen ? <X size={18} /> : <Menu size={18} />}
      </button>

      {/* Mobile slide-out menu */}
      {mobileMenuOpen && (
        <div
          className={styles.mobileOverlay}
          onClick={() => setMobileMenuOpen(false)}
          onTouchStart={(e) => { touchStartXRef.current = e.changedTouches[0]?.clientX ?? null }}
          onTouchEnd={(e) => {
            const startX = touchStartXRef.current
            const endX = e.changedTouches[0]?.clientX
            if (startX != null && endX != null && Math.abs(endX - startX) > SWIPE_CLOSE_THRESHOLD) {
              setMobileMenuOpen(false)
            }
            touchStartXRef.current = null
          }}
        >
          <nav className={styles.mobileMenu} onClick={e => e.stopPropagation()}>
            <div className={styles.mobileHeader}>
              <span className={styles.mobileTitle}>Navigation</span>
              <button
                className={styles.mobileClose}
                onClick={() => setMobileMenuOpen(false)}
                aria-label="Close menu"
              >
                <X size={18} />
              </button>
            </div>

            <div className={styles.mobileSection}>
              <span className={styles.mobileSectionTitle}>Core</span>
              {coreNav.map(item => {
                const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`)
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`${styles.mobileNavItem} ${isActive ? styles.mobileNavItemActive : ''}`}
                    onClick={handleNavClick}
                  >
                    {item.icon}
                    <span>{item.label}</span>
                  </Link>
                )
              })}
            </div>

            <div className={styles.mobileSection}>
              <span className={styles.mobileSectionTitle}>Utilities</span>
              {utilityLinks.map(item => {
                const isActive = pathname === item.href || pathname.startsWith(`${item.href}/`)
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    className={`${styles.mobileNavItem} ${isActive ? styles.mobileNavItemActive : ''}`}
                    onClick={handleNavClick}
                  >
                    {item.icon}
                    <span>{item.label}</span>
                  </Link>
                )
              })}
            </div>

            <div className={styles.mobileSection}>
              <span className={styles.mobileSectionTitle}>Wiki</span>
              <a
                href="https://github.com/samugit83/redamon/wiki"
                target="_blank"
                rel="noopener noreferrer"
                className={styles.mobileNavItem}
                onClick={handleNavClick}
              >
                <BookOpen size={16} />
                <span>Documentation</span>
              </a>
            </div>

            <div className={styles.mobileDivider} />

            <div className={styles.mobileBottom}>
              <ProjectSelector />
              <div className={styles.mobileRow}>
                <ThemeToggle />
                <UserSelector />
              </div>
            </div>
          </nav>
        </div>
      )}
    </header>
  )
}

'use client'

import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { Crosshair, Target, Table2, Terminal, Bot } from 'lucide-react'
import { useIsMobile } from '@/hooks/useMediaQuery'
import styles from './MobileBottomNav.module.css'

const NAV_ITEMS = [
  { label: 'Red Zone', href: '/graph', icon: Crosshair, id: 'graph' },
  { label: 'Attack', view: 'attack', icon: Target, id: 'attack' },
  { label: 'Table', view: 'table', icon: Table2, id: 'table' },
  { label: 'Shells', view: 'sessions', icon: Terminal, id: 'sessions' },
  { label: 'AI', view: 'ai', icon: Bot, id: 'ai' },
]

export function MobileBottomNav() {
  const pathname = usePathname()
  const searchParams = useSearchParams()
  const router = useRouter()
  const isMobile = useIsMobile()

  if (!isMobile) return null

  const activeView = searchParams.get('view')
  const isGraphPage = pathname === '/graph'

  const handleNav = (item: typeof NAV_ITEMS[number]) => {
    if (item.href) {
      router.push(item.href)
    } else if (item.view) {
      const params = new URLSearchParams(searchParams.toString())
      params.set('view', item.view)
      router.push(`/graph?${params.toString()}`)
    }
  }

  return (
    <nav className={styles.bottomNav} aria-label="Main navigation">
      <div className={styles.navInner}>
        {NAV_ITEMS.map(item => {
          const Icon = item.icon
          const isActive = item.id === 'graph'
            ? isGraphPage && !activeView
            : isGraphPage && activeView === item.view
          return (
            <button
              key={item.id}
              className={`${styles.navItem} ${isActive ? styles.navItemActive : ''}`}
              onClick={() => handleNav(item)}
              aria-label={item.label}
              aria-current={isActive ? 'page' : undefined}
            >
              <Icon size={20} aria-hidden="true" />
              <span className={styles.navLabel}>{item.label}</span>
            </button>
          )
        })}
      </div>
    </nav>
  )
}

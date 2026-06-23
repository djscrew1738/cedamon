'use client'

import { useState, useRef, useEffect, useCallback, type ReactNode } from 'react'
import {
  Monitor,
  Sun,
  Moon,
  Search,
  GitBranch,
  Users,
  Settings,
} from 'lucide-react'
import styles from './CommandPalette.module.css'

export interface CommandAction {
  id: string
  label: string
  icon?: ReactNode
  shortcut?: string
  onRun: () => void
}

interface CommandPaletteProps {
  /** All available actions shown in the palette. */
  actions: CommandAction[]
  /** Whether the palette is currently visible. */
  isOpen: boolean
  /** Called when the user dismisses the palette. */
  onClose: () => void
}

export function CommandPalette({ actions, isOpen, onClose }: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const [activeIndex, setActiveIndex] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLUListElement>(null)

  const filtered = actions.filter((a) =>
    a.label.toLowerCase().includes(query.toLowerCase()),
  )

  // Reset state when opening
  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setActiveIndex(0)
      // Focus the input on the next frame so the dialog is mounted
      requestAnimationFrame(() => inputRef.current?.focus())
    }
  }, [isOpen])

  // Close on Escape
  useEffect(() => {
    if (!isOpen) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [isOpen, onClose])

  const runSelected = useCallback(
    (index: number) => {
      const action = filtered[index]
      if (action) {
        action.onRun()
        onClose()
      }
    },
    [filtered, onClose],
  )

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setActiveIndex((prev) => (prev + 1) % Math.max(filtered.length, 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setActiveIndex((prev) => (prev - 1 + filtered.length) % Math.max(filtered.length, 1))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        runSelected(activeIndex)
      }
    },
    [filtered.length, activeIndex, runSelected],
  )

  // Scroll active item into view
  useEffect(() => {
    const list = listRef.current
    if (!list) return
    const item = list.children[activeIndex] as HTMLElement | undefined
    item?.scrollIntoView({ block: 'nearest' })
  }, [activeIndex])

  if (!isOpen) return null

  return (
    <div
      className={styles.overlay}
      onClick={(e) => { if (e.target === e.currentTarget) onClose() }}
      role="dialog"
      aria-modal="true"
      aria-label="Command palette"
    >
      <div className={styles.dialog}>
        <input
          ref={inputRef}
          className={styles.input}
          type="text"
          placeholder="Search actions…"
          value={query}
          onChange={(e) => { setQuery(e.target.value); setActiveIndex(0) }}
          onKeyDown={handleKeyDown}
          aria-label="Search commands"
        />
        {filtered.length > 0 ? (
          <ul ref={listRef} className={styles.list} role="listbox">
            {filtered.map((action, i) => (
              <li
                key={action.id}
                className={`${styles.item} ${i === activeIndex ? styles.itemActive : ''}`}
                role="option"
                aria-selected={i === activeIndex}
                onMouseEnter={() => setActiveIndex(i)}
                onMouseDown={(e) => { e.preventDefault(); runSelected(i) }}
              >
                <span className={styles.itemIcon}>
                  {action.icon ?? <Search size={14} />}
                </span>
                <span className={styles.itemLabel}>{action.label}</span>
                {action.shortcut && (
                  <span className={styles.itemShortcut}>{action.shortcut}</span>
                )}
              </li>
            ))}
          </ul>
        ) : (
          <div className={styles.noResults}>No matching actions</div>
        )}
      </div>
    </div>
  )
}

/**
 * Builds a default set of actions for the graph page.
 */
export function useGraphPaletteActions(
  router: { push: (url: string) => void },
  toggleTheme: () => void,
  theme: string,
  graphNodeNames?: string[],
  onSelectNode?: (name: string) => void,
): CommandAction[] {
  return [
    {
      id: 'go-projects',
      label: 'Go to Projects',
      icon: <GitBranch size={14} />,
      shortcut: 'G P',
      onRun: () => router.push('/projects'),
    },
    {
      id: 'go-users',
      label: 'Go to Users',
      icon: <Users size={14} />,
      shortcut: 'G U',
      onRun: () => router.push('/settings/users'),
    },
    {
      id: 'go-settings',
      label: 'Go to Settings',
      icon: <Settings size={14} />,
      shortcut: 'G S',
      onRun: () => router.push('/settings'),
    },
    {
      id: 'toggle-theme',
      label: `Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`,
      icon: theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />,
      shortcut: 'T T',
      onRun: () => toggleTheme(),
    },
    ...(graphNodeNames
      ? graphNodeNames.map((name) => ({
          id: `node-${name}` as const,
          label: `Search node: ${name}`,
          icon: <Search size={14} />,
          onRun: () => onSelectNode?.(name),
        }))
      : []),
  ]
}

'use client'

import { useState, useCallback } from 'react'
import { Info, Check, Copy, ExternalLink, ChevronDown, ChevronRight } from 'lucide-react'
import { useVersionCheck } from '@/hooks/useVersionCheck'
import { WikiInfoButton } from '@/components/ui'
import styles from './Settings.module.css'

export function SystemSection() {
  const { currentVersion, latestVersion, changelog, updateAvailable, loading } = useVersionCheck()

  const [copied, setCopied] = useState(false)
  const [expandedVersions, setExpandedVersions] = useState<Set<string>>(new Set())

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText('./redamon.sh update').then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }, [])

  const toggleVersion = (version: string) => {
    setExpandedVersions(prev => {
      const next = new Set(prev)
      if (next.has(version)) next.delete(version)
      else next.add(version)
      return next
    })
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader}>
        <h2 className={styles.sectionTitle} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
          <Info size={16} /> System
          <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Troubleshooting" title="Open Troubleshooting wiki page" />
        </h2>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        {/* Version info */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
          <span style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
            Current version: <strong style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)' }}>v{currentVersion}</strong>
          </span>

          {latestVersion && !updateAvailable && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: '4px',
              fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '4px',
              background: 'var(--status-success-bg)', color: 'var(--status-success-text)',
            }}>
              Up to date
            </span>
          )}

          {updateAvailable && latestVersion && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: '4px',
              fontSize: '11px', fontWeight: 600, padding: '2px 8px', borderRadius: '4px',
              background: 'var(--status-warning-bg)', color: 'var(--status-warning-text)',
            }}>
              v{latestVersion} available
            </span>
          )}
        </div>

        {/* Update instructions */}
        {updateAvailable && (
          <div style={{
            padding: '12px', borderRadius: '8px',
            background: 'var(--bg-tertiary)', border: '1px solid var(--border-default)',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
              <code style={{
                padding: '6px 10px', borderRadius: '4px',
                background: 'var(--bg-primary)',
                fontFamily: 'var(--font-mono)', fontSize: '13px',
                border: '1px solid var(--border-subtle)',
              }}>
                ./redamon.sh update
              </code>
              <button
                onClick={handleCopy}
                type="button"
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: '4px',
                  padding: '6px 10px', fontSize: '12px',
                  background: 'none', border: '1px solid var(--border-default)',
                  borderRadius: '6px', cursor: 'pointer',
                  color: 'var(--text-secondary)',
                }}
              >
                {copied ? <Check size={12} /> : <Copy size={12} />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
          </div>
        )}

        {/* Changelog */}
        {!loading && changelog && changelog.length > 0 && (
          <>
            <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
              Changes since v{currentVersion}:
            </span>
            <div style={{
              maxHeight: '250px', overflowY: 'auto',
              border: '1px solid var(--border-default)', borderRadius: '6px',
              background: 'var(--bg-primary)',
            }}>
              {changelog.map((entry: { version: string; date: string; sections: { title: string; items: string[] }[] }) => {
                const isExpanded = expandedVersions.has(entry.version)
                return (
                  <div key={entry.version} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                    <button
                      type="button"
                      onClick={() => toggleVersion(entry.version)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: '6px',
                        width: '100%', padding: '6px 10px', background: 'none',
                        border: 'none', cursor: 'pointer', fontSize: '12px',
                        color: 'var(--text-primary)', textAlign: 'left',
                      }}
                    >
                      {isExpanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                      <strong style={{ fontFamily: 'var(--font-mono)' }}>v{entry.version}</strong>
                      <span style={{ color: 'var(--text-tertiary)', fontSize: '11px', marginLeft: 'auto' }}>{entry.date}</span>
                    </button>
                    {isExpanded && (
                      <div style={{ padding: '0 10px 8px 28px' }}>
                        {entry.sections.map((section: { title: string; items: string[] }) => (
                          <div key={section.title} style={{ marginTop: '4px' }}>
                            <div style={{ fontSize: '10px', fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                              {section.title}
                            </div>
                            <ul style={{ margin: '2px 0 0', paddingLeft: '16px', listStyle: 'disc' }}>
                              {section.items.map((item: string, i: number) => (
                                <li key={i} style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>{item}</li>
                              ))}
                            </ul>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </>
        )}

        {/* Links */}
        <div style={{ display: 'flex', gap: '12px', fontSize: '11px' }}>
          <a
            href="https://github.com/samugit83/redamon/blob/master/CHANGELOG.md"
            target="_blank"
            rel="noopener noreferrer"
            style={{ display: 'flex', alignItems: 'center', gap: '4px', color: 'var(--text-tertiary)', textDecoration: 'none' }}
          >
            <ExternalLink size={11} /> Changelog
          </a>
        </div>
      </div>
    </div>
  )
}

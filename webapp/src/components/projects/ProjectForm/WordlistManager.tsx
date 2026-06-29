'use client'

import { useState, useEffect, useCallback } from 'react'
import { Upload, Download, X, Loader2, CheckCircle2, Globe } from 'lucide-react'
import styles from './WordlistManager.module.css'

interface WordlistEntry {
  name: string
  path: string
  size: string
  desc: string
  downloaded?: boolean
}

interface WordlistCatalog {
  category: string
  lists: WordlistEntry[]
}

interface CustomWordlist {
  name: string
  path: string
  size: number
}

interface WordlistManagerProps {
  /** Currently selected wordlist path */
  value: string
  /** Called when user selects a wordlist */
  onChange: (path: string) => void
  /** Project ID for custom uploads (omit in create mode) */
  projectId?: string
  /** Label override */
  label?: string
  /** Which categories to show from SecLists. Omit to show all. */
  categories?: string[]
  /** Additional built-in wordlists specific to this tool */
  extraBuiltins?: WordlistEntry[]
  /** Whether to show custom upload UI */
  allowUpload?: boolean
  /** Accept filter for upload */
  uploadAccept?: string
}

export function WordlistManager({
  value,
  onChange,
  projectId,
  label = 'Wordlist',
  categories,
  extraBuiltins,
  allowUpload = true,
  uploadAccept = '.txt',
}: WordlistManagerProps) {
  const [catalog, setCatalog] = useState<WordlistCatalog[]>([])
  const [catalogLoading, setCatalogLoading] = useState(false)
  const [catalogOpen, setCatalogOpen] = useState(false)
  const [downloading, setDownloading] = useState<string | null>(null)
  const [downloadError, setDownloadError] = useState<string | null>(null)

  // Custom wordlists
  const [customWordlists, setCustomWordlists] = useState<CustomWordlist[]>([])
  const [isUploading, setIsUploading] = useState(false)
  const [uploadError, setUploadError] = useState<string | null>(null)

  const canUpload = allowUpload && !!projectId

  // Fetch SecLists catalog
  const fetchCatalog = useCallback(async () => {
    setCatalogLoading(true)
    try {
      const res = await fetch('/api/wordlists/seclists?action=list')
      if (res.ok) {
        const data = await res.json()
        let cats = data.catalog || []
        if (categories) {
          cats = cats.filter((c: WordlistCatalog) => categories.includes(c.category))
        }
        setCatalog(cats)
      }
    } catch {
      // Silently fail
    } finally {
      setCatalogLoading(false)
    }
  }, [categories])

  // Fetch custom wordlists
  const fetchCustom = useCallback(async () => {
    if (!projectId) return
    try {
      const res = await fetch(`/api/projects/${projectId}/wordlists`)
      if (res.ok) {
        const json = await res.json()
        setCustomWordlists(json.wordlists || [])
      }
    } catch {
      // Silently fail
    }
  }, [projectId])

  useEffect(() => {
    fetchCatalog()
  }, [fetchCatalog])

  useEffect(() => {
    fetchCustom()
  }, [fetchCustom])

  // Download a SecList wordlist
  const handleDownload = async (entry: WordlistEntry) => {
    setDownloading(entry.path)
    setDownloadError(null)
    try {
      const res = await fetch(
        `/api/wordlists/seclists?action=download&path=${encodeURIComponent(entry.path)}`
      )
      const data = await res.json()
      if (res.ok) {
        // Mark as downloaded in local catalog
        setCatalog(prev =>
          prev.map(cat => ({
            ...cat,
            lists: cat.lists.map(l =>
              l.path === entry.path ? { ...l, downloaded: true } : l
            ),
          }))
        )
        // Auto-select if nothing selected
        if (!value || value === '') {
          onChange(data.path)
        }
      } else {
        setDownloadError(data.error || 'Download failed')
      }
    } catch {
      setDownloadError('Network error — download failed')
    } finally {
      setDownloading(null)
    }
  }

  // Upload custom wordlist
  const handleUpload = async (file: File) => {
    if (!projectId) return
    setIsUploading(true)
    setUploadError(null)
    try {
      const formData = new FormData()
      formData.append('file', file)
      const res = await fetch(`/api/projects/${projectId}/wordlists`, {
        method: 'POST',
        body: formData,
      })
      const result = await res.json()
      if (!res.ok) {
        setUploadError(result.error || 'Upload failed')
        return
      }
      setCustomWordlists(result.wordlists || [])
      if (result.uploaded?.path) {
        onChange(result.uploaded.path)
      }
    } catch {
      setUploadError('Upload failed')
    } finally {
      setIsUploading(false)
    }
  }

  const handleDeleteCustom = async (name: string) => {
    if (!projectId) return
    try {
      const res = await fetch(
        `/api/projects/${projectId}/wordlists?name=${encodeURIComponent(name)}`,
        { method: 'DELETE' }
      )
      if (res.ok) {
        const result = await res.json()
        setCustomWordlists(result.wordlists || [])
        const deletedPath = `/app/recon/wordlists/${projectId}/${name}`
        if (value === deletedPath) {
          onChange('')
        }
      }
    } catch {
      // Silently fail
    }
  }

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  return (
    <div className={styles.wrapper}>
      <label className={styles.label}>{label}</label>

      <div className={styles.selector}>
        <select
          className="select"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          style={{ flex: 1 }}
        >
          <option value="">— Select a wordlist —</option>

          {extraBuiltins && extraBuiltins.length > 0 && (
            <optgroup label="Built-in">
              {extraBuiltins.map(wl => (
                <option key={wl.path} value={wl.path}>{wl.name} ({wl.size})</option>
              ))}
            </optgroup>
          )}

          {catalog.map(cat => (
            <optgroup key={cat.category} label={`SecLists — ${cat.category}`}>
              {cat.lists
                .filter(l => l.downloaded)
                .map(l => (
                  <option key={l.path} value={l.path}>{l.name} ({l.size})</option>
                ))}
            </optgroup>
          ))}

          {customWordlists.length > 0 && (
            <optgroup label="Your Custom Lists">
              {customWordlists.map(wl => (
                <option key={wl.path} value={wl.path}>
                  {wl.name} ({formatSize(wl.size)})
                </option>
              ))}
            </optgroup>
          )}
        </select>

        {/* Download SecLists button */}
        <button
          type="button"
          className={styles.actionBtn}
          onClick={() => setCatalogOpen(!catalogOpen)}
          title="Download wordlists from SecLists"
        >
          <Globe size={14} />
          SecLists
        </button>

        {/* Upload custom button */}
        {allowUpload && (
          <>
            <input
              type="file"
              accept={uploadAccept}
              style={{ display: 'none' }}
              id={`wl-upload-${label.replace(/\s+/g, '-')}`}
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) handleUpload(file)
                e.target.value = ''
              }}
            />
            <button
              type="button"
              className={styles.actionBtn}
              onClick={() => document.getElementById(`wl-upload-${label.replace(/\s+/g, '-')}`)?.click()}
              disabled={isUploading || !canUpload}
              title={canUpload ? 'Upload a custom wordlist' : 'Save project first to upload'}
            >
              {isUploading ? <Loader2 size={14} className={styles.spinner} /> : <Upload size={14} />}
            </button>
          </>
        )}
      </div>

      {/* Upload error */}
      {uploadError && (
        <p className={styles.error}>{uploadError}</p>
      )}

      {/* SecLists catalog panel */}
      {catalogOpen && (
        <div className={styles.catalog}>
          <div className={styles.catalogHeader}>
            <h4 className={styles.catalogTitle}>SecLists — Download Wordlists</h4>
            <button
              type="button"
              className={styles.catalogClose}
              onClick={() => setCatalogOpen(false)}
            >
              <X size={14} />
            </button>
          </div>

          {catalogLoading ? (
            <div className={styles.catalogLoading}>
              <Loader2 size={16} className={styles.spinner} />
              Loading catalog...
            </div>
          ) : downloadError ? (
            <p className={styles.error}>{downloadError}</p>
          ) : (
            catalog.map(cat => (
              <div key={cat.category} className={styles.catalogGroup}>
                <h5 className={styles.catalogGroupTitle}>{cat.category}</h5>
                {cat.lists.map(entry => (
                  <div
                    key={entry.path}
                    className={`${styles.catalogItem} ${entry.downloaded ? styles.catalogItemCached : ''}`}
                  >
                    <div className={styles.catalogItemInfo}>
                      <span className={styles.catalogItemName}>{entry.name}</span>
                      <span className={styles.catalogItemMeta}>
                        {entry.size} — {entry.desc}
                      </span>
                    </div>
                    <button
                      type="button"
                      className={styles.downloadBtn}
                      onClick={() => handleDownload(entry)}
                      disabled={downloading === entry.path || entry.downloaded}
                    >
                      {downloading === entry.path ? (
                        <Loader2 size={12} className={styles.spinner} />
                      ) : entry.downloaded ? (
                        <CheckCircle2 size={12} />
                      ) : (
                        <Download size={12} />
                      )}
                      {entry.downloaded ? 'Cached' : downloading === entry.path ? '...' : 'Get'}
                    </button>
                  </div>
                ))}
              </div>
            ))
          )}
        </div>
      )}

      {/* Custom wordlist manager */}
      {customWordlists.length > 0 && canUpload && (
        <div className={styles.customList}>
          <label className={styles.label}>Uploaded Wordlists</label>
          {customWordlists.map(wl => (
            <div key={wl.name} className={styles.customItem}>
              <span>{wl.name} ({formatSize(wl.size)})</span>
              <button
                type="button"
                className={styles.deleteBtn}
                onClick={() => handleDeleteCustom(wl.name)}
                title="Delete"
              >
                <X size={12} />
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

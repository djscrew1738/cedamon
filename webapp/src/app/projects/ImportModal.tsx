'use client'

import { useState, useRef } from 'react'
import { Upload, Loader2, CheckCircle, AlertCircle, FileArchive } from 'lucide-react'
import { useToast } from '@/components/ui'
import styles from './page.module.css'

interface ImportStats {
  conversations: number
  messages: number
  remediations: number
  reports: number
  neo4jNodes: number
  neo4jRelationships: number
  artifacts: number
}

interface ImportResult {
  success: boolean
  projectId: string
  projectName: string
  stats: ImportStats
}

interface ImportModalProps {
  isOpen: boolean
  userId: string
  onClose: () => void
  onSuccess: () => void
}

export function ImportModal({ isOpen, userId, onClose, onSuccess }: ImportModalProps) {
  const toast = useToast()
  const [file, setFile] = useState<File | null>(null)
  const [status, setStatus] = useState<'idle' | 'uploading' | 'success' | 'error'>('idle')
  const [result, setResult] = useState<ImportResult | null>(null)
  const [errorMessage, setErrorMessage] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  if (!isOpen) return null

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0] || null
    setFile(selected)
    setStatus('idle')
    setResult(null)
    setErrorMessage('')
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file) return

    setStatus('uploading')
    setErrorMessage('')

    try {
      const formData = new FormData()
      formData.append('file', file)

      const res = await fetch(`/api/projects/import?userId=${userId}`, {
        method: 'POST',
        body: formData,
      })

      if (res.ok) {
        const data: ImportResult = await res.json()
        setResult(data)
        setStatus('success')
        toast.success('Project imported')
        onSuccess()
      } else {
        const err = await res.json()
        setErrorMessage(err.error || 'Import failed')
        setStatus('error')
        toast.error('Import failed')
      }
    } catch (err) {
      setErrorMessage(err instanceof Error ? err.message : 'Import failed')
      setStatus('error')
      toast.error('Import failed')
    }
  }

  const handleClose = () => {
    setFile(null)
    setStatus('idle')
    setResult(null)
    setErrorMessage('')
    onClose()
  }

  return (
    <div className={styles.modalOverlay} onClick={handleClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <h2 className={styles.modalTitle}>Import Project</h2>

        {status === 'idle' && (
          <form onSubmit={handleSubmit}>
            <div className="formGroup">
              <label className="formLabel">Project Backup File</label>
              <div
                className={`${styles.importDropzone} ${file ? styles.importDropzoneHasFile : ''}`}
                onClick={() => fileInputRef.current?.click()}
              >
                {file ? (
                  <div className={styles.importFileInfo}>
                    <FileArchive size={16} />
                    <span className={styles.importFileName}>{file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)</span>
                  </div>
                ) : (
                  <div className={styles.importPlaceholder}>
                    <Upload size={24} className={styles.importUploadIcon} />
                    Click to select a RedAmon export ZIP file
                  </div>
                )}
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".zip"
                  onChange={handleFileChange}
                  style={{ display: 'none' }}
                />
              </div>
              <p className={styles.importHint}>
                The project will be created under the currently selected user.
              </p>
            </div>
            <div className={styles.modalActions}>
              <button
                type="button"
                className="secondaryButton"
                onClick={handleClose}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="primaryButton"
                disabled={!file}
              >
                <Upload size={14} />
                Import
              </button>
            </div>
          </form>
        )}

        {status === 'uploading' && (
          <div className={styles.importLoading}>
            <Loader2 size={32} className={styles.importSpinner} />
            <p className={styles.importLoadingText}>
              Importing project data...
            </p>
            <p className={styles.importLoadingSubtext}>
              This may take a moment for large projects.
            </p>
          </div>
        )}

        {status === 'success' && result && (
          <div className={styles.importSuccess}>
            <div className={styles.importSuccessHeader}>
              <CheckCircle size={20} />
              <span className={styles.importSuccessTitle}>Import Successful</span>
            </div>
            <p className={styles.importSuccessMsg}>
              Project &quot;{result.projectName}&quot; has been restored.
            </p>
            <div className={styles.importStats}>
              <span>Conversations: {result.stats.conversations}</span>
              <span>Messages: {result.stats.messages}</span>
              <span>Remediations: {result.stats.remediations}</span>
              <span>Reports: {result.stats.reports}</span>
              <span>Graph Nodes: {result.stats.neo4jNodes}</span>
              <span>Relationships: {result.stats.neo4jRelationships}</span>
              <span>Artifacts: {result.stats.artifacts}</span>
            </div>
            <div className={styles.modalActions}>
              <button className="primaryButton" onClick={handleClose}>
                Done
              </button>
            </div>
          </div>
        )}

        {status === 'error' && (
          <div className={styles.importError}>
            <div className={styles.importErrorHeader}>
              <AlertCircle size={20} />
              <span className={styles.importErrorTitle}>Import Failed</span>
            </div>
            <p className={styles.importErrorMsg}>
              {errorMessage}
            </p>
            <div className={styles.modalActions}>
              <button className="secondaryButton" onClick={handleClose}>
                Close
              </button>
              <button className="primaryButton" onClick={() => { setStatus('idle'); setErrorMessage('') }}>
                Try Again
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

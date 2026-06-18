'use client'

import { useState, useCallback, useEffect } from 'react'
import { Pencil, Trash2, Loader2, Upload, Download, BookOpen } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast } from '@/components/ui'
import styles from '@/components/settings/Settings.module.css'

export function ChatSkillsTab() {
  const { userId } = useProject()
  const { alertError, alert: showAlert, confirm: showConfirm } = useAlertModal()
  const toast = useToast()

  const [chatSkills, setChatSkills] = useState<{ id: string; name: string; description?: string | null; category?: string | null; createdAt: string }[]>([])
  const [chatSkillsLoading, setChatSkillsLoading] = useState(true)
  const [chatSkillNameModal, setChatSkillNameModal] = useState(false)
  const [pendingChatSkillContent, setPendingChatSkillContent] = useState('')
  const [pendingChatSkillName, setPendingChatSkillName] = useState('')
  const [pendingChatSkillDescription, setPendingChatSkillDescription] = useState('')
  const [pendingChatSkillCategory, setPendingChatSkillCategory] = useState('general')
  const [chatSkillUploading, setChatSkillUploading] = useState(false)
  const [editChatDescModal, setEditChatDescModal] = useState(false)
  const [editingChatSkillId, setEditingChatSkillId] = useState('')
  const [editingChatSkillDescription, setEditingChatSkillDescription] = useState('')
  const [editChatDescSaving, setEditChatDescSaving] = useState(false)
  const [importingChatSkills, setImportingChatSkills] = useState(false)

  const fetchChatSkills = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills`)
      if (resp.ok) setChatSkills(await resp.json())
    } catch (err) {
      console.error('Failed to fetch chat skills:', err)
    } finally {
      setChatSkillsLoading(false)
    }
  }, [userId])

  useEffect(() => { fetchChatSkills() }, [fetchChatSkills])

  const handleChatSkillUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !userId) return
    const reader = new FileReader()
    reader.onload = () => {
      setPendingChatSkillContent(reader.result as string)
      setPendingChatSkillName(file.name.replace(/\.md$/i, ''))
      setPendingChatSkillCategory('general')
      setChatSkillNameModal(true)
    }
    reader.readAsText(file)
    e.target.value = ''
  }, [userId])

  const confirmChatSkillUpload = useCallback(async () => {
    if (!userId || !pendingChatSkillName.trim()) return
    setChatSkillUploading(true)
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: pendingChatSkillName.trim(),
          description: pendingChatSkillDescription.trim() || null,
          category: pendingChatSkillCategory,
          content: pendingChatSkillContent,
        }),
      })
      if (resp.ok) {
        fetchChatSkills()
        setChatSkillNameModal(false)
        setPendingChatSkillContent('')
        setPendingChatSkillName('')
        setPendingChatSkillDescription('')
        setPendingChatSkillCategory('general')
        toast.success('Chat skill uploaded')
      } else {
        const err = await resp.json()
        alertError(err.error || 'Failed to upload chat skill')
      }
    } catch (err) {
      console.error('Failed to upload chat skill:', err)
      toast.error('Failed to upload chat skill')
    } finally {
      setChatSkillUploading(false)
    }
  }, [userId, pendingChatSkillName, pendingChatSkillDescription, pendingChatSkillCategory, pendingChatSkillContent, fetchChatSkills])

  const downloadChatSkill = useCallback(async (skillId: string, skillName: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills/${skillId}`)
      if (resp.ok) {
        const skill = await resp.json()
        const blob = new Blob([skill.content], { type: 'text/markdown' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `${skillName}.md`
        a.click()
        URL.revokeObjectURL(url)
      }
    } catch (err) {
      console.error('Failed to download chat skill:', err)
    }
  }, [userId])

  const deleteChatSkill = useCallback(async (skillId: string) => {
    if (!userId || !(await showConfirm('Delete this chat skill?'))) return
    try {
      await fetch(`/api/users/${userId}/chat-skills/${skillId}`, { method: 'DELETE' })
      fetchChatSkills()
      toast.success('Chat skill deleted')
    } catch (err) {
      console.error('Failed to delete chat skill:', err)
      toast.error('Failed to delete chat skill')
    }
  }, [userId, fetchChatSkills])

  const openEditChatDescription = useCallback(async (skillId: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills/${skillId}`)
      if (resp.ok) {
        const skill = await resp.json()
        setEditingChatSkillId(skillId)
        setEditingChatSkillDescription(skill.description || '')
        setEditChatDescModal(true)
      }
    } catch (err) {
      console.error('Failed to fetch chat skill:', err)
    }
  }, [userId])

  const saveEditChatDescription = useCallback(async () => {
    if (!userId || !editingChatSkillId) return
    setEditChatDescSaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills/${editingChatSkillId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: editingChatSkillDescription.trim() || null }),
      })
      if (resp.ok) {
        fetchChatSkills()
        setEditChatDescModal(false)
        setEditingChatSkillId('')
        setEditingChatSkillDescription('')
        toast.success('Chat skill description updated')
      } else {
        const err = await resp.json()
        alertError(err.error || 'Failed to update description')
      }
    } catch (err) {
      console.error('Failed to update chat skill description:', err)
      toast.error('Failed to update description')
    } finally {
      setEditChatDescSaving(false)
    }
  }, [userId, editingChatSkillId, editingChatSkillDescription, fetchChatSkills])

  const importCommunityChatSkills = useCallback(async () => {
    if (!userId) return
    setImportingChatSkills(true)
    try {
      const resp = await fetch(`/api/users/${userId}/chat-skills/import-community`, { method: 'POST' })
      const data = await resp.json()
      if (resp.ok) {
        fetchChatSkills()
        showAlert(data.message || `Imported ${data.imported ?? 0} community chat skill(s).`)
      } else {
        alertError(data.error || 'Failed to import community chat skills')
      }
    } catch (err) {
      console.error('Failed to import community chat skills:', err)
    } finally {
      setImportingChatSkills(false)
    }
  }, [userId, fetchChatSkills])

  return (
    <>
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
            <BookOpen size={16} /> Chat Skills
          </h2>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              className="secondaryButton"
              onClick={importCommunityChatSkills}
              disabled={importingChatSkills}
            >
              {importingChatSkills ? <Loader2 size={14} className={styles.spin} /> : <Download size={14} />}
              Import from Community
            </button>
            <label className="primaryButton" style={{ cursor: 'pointer' }}>
              <Upload size={14} /> Upload Skill (.md)
              <input
                type="file"
                accept=".md"
                style={{ display: 'none' }}
                onChange={handleChatSkillUpload}
              />
            </label>
          </div>
        </div>
        <p className={styles.sectionHint}>
          Upload and manage on-demand reference skills for the AI agent chat. Unlike Agent Skills (which drive attack classification and phase-aware workflows), Chat Skills are tactical reference docs that you inject into the agent&apos;s context on the fly using <code>/skill &lt;name&gt;</code> in the chat.
        </p>

        {chatSkillsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : chatSkills.length === 0 ? (
          <div className={styles.emptyState}>No Chat Skills yet. Click Import from Community to add ready-to-use reference skills, or upload your own .md files.</div>
        ) : (
          <div className={styles.providerList}>
            {chatSkills.map(skill => (
              <div key={skill.id} className={styles.providerCard}>
                <span className={styles.providerIcon}><BookOpen size={16} /></span>
                <div className={styles.providerInfo}>
                  <div className={styles.providerName}>
                    {skill.name}
                    {skill.category && (
                      <span style={{
                        marginLeft: '8px',
                        fontSize: '10px',
                        fontWeight: 500,
                        padding: '2px 6px',
                        borderRadius: '4px',
                        background: 'var(--bg-tertiary)',
                        color: 'var(--text-secondary)',
                        textTransform: 'uppercase',
                        letterSpacing: '0.03em',
                      }}>
                        {skill.category}
                      </span>
                    )}
                  </div>
                  <div className={styles.providerMeta}>
                    {skill.description || <span style={{ opacity: 0.5, fontStyle: 'italic' }}>No description</span>}
                  </div>
                  <div className={styles.providerMeta}>
                    Uploaded {new Date(skill.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <div className={styles.providerActions}>
                  <button className="iconButton" title="Edit description" onClick={() => openEditChatDescription(skill.id)}>
                    <Pencil size={14} />
                  </button>
                  <button className="iconButton" title="Download" onClick={() => downloadChatSkill(skill.id, skill.name)}>
                    <Download size={14} />
                  </button>
                  <button className="iconButton" title="Delete" onClick={() => deleteChatSkill(skill.id)}>
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Chat Skill upload modal */}
      <Modal
        isOpen={chatSkillNameModal}
        onClose={() => { setChatSkillNameModal(false); setPendingChatSkillContent(''); setPendingChatSkillName(''); setPendingChatSkillDescription(''); setPendingChatSkillCategory('general') }}
        title="Upload Chat Skill"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setChatSkillNameModal(false); setPendingChatSkillContent(''); setPendingChatSkillName(''); setPendingChatSkillDescription(''); setPendingChatSkillCategory('general') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={!pendingChatSkillName.trim() || chatSkillUploading}
              onClick={confirmChatSkillUpload}
            >
              {chatSkillUploading ? <Loader2 size={14} className={styles.spin} /> : <Upload size={14} />}
              Upload
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Skill Name</label>
          <input
            className="textInput"
            type="text"
            value={pendingChatSkillName}
            onChange={(e) => setPendingChatSkillName(e.target.value)}
            placeholder="e.g. OWASP Top 10 Reference"
            autoFocus
          />
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel">Description</label>
          <textarea
            className="textInput"
            rows={3}
            value={pendingChatSkillDescription}
            onChange={(e) => setPendingChatSkillDescription(e.target.value)}
            placeholder="e.g. Quick reference for OWASP Top 10 vulnerability categories"
            maxLength={500}
          />
          <span className="formHint">
            Optional. Helps you remember what this skill covers.
          </span>
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel">Category</label>
          <select
            className="textInput"
            value={pendingChatSkillCategory}
            onChange={(e) => setPendingChatSkillCategory(e.target.value)}
          >
            <option value="general">general</option>
            <option value="vulnerabilities">vulnerabilities</option>
            <option value="tooling">tooling</option>
            <option value="scan_modes">scan_modes</option>
            <option value="frameworks">frameworks</option>
            <option value="technologies">technologies</option>
            <option value="protocols">protocols</option>
            <option value="coordination">coordination</option>
            <option value="cloud">cloud</option>
            <option value="mobile">mobile</option>
            <option value="api_security">api_security</option>
            <option value="wireless">wireless</option>
            <option value="network">network</option>
            <option value="active_directory">active_directory</option>
            <option value="social_engineering">social_engineering</option>
            <option value="reporting">reporting</option>
          </select>
          <span className="formHint">
            Categorize this skill for easier browsing.
          </span>
        </div>
      </Modal>

      {/* Chat Skill edit description modal */}
      <Modal
        isOpen={editChatDescModal}
        onClose={() => { setEditChatDescModal(false); setEditingChatSkillId(''); setEditingChatSkillDescription('') }}
        title="Edit Chat Skill Description"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setEditChatDescModal(false); setEditingChatSkillId(''); setEditingChatSkillDescription('') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={editChatDescSaving}
              onClick={saveEditChatDescription}
            >
              {editChatDescSaving ? <Loader2 size={14} className={styles.spin} /> : <Pencil size={14} />}
              Save
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Description</label>
          <textarea
            className="textInput"
            rows={3}
            value={editingChatSkillDescription}
            onChange={(e) => setEditingChatSkillDescription(e.target.value)}
            placeholder="e.g. Quick reference for OWASP Top 10 vulnerability categories"
            maxLength={500}
            autoFocus
          />
          <span className="formHint">
            Optional description to help you remember what this skill covers.
          </span>
        </div>
      </Modal>
    </>
  )
}

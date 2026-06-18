'use client'

import { useState, useCallback, useEffect } from 'react'
import { Plus, Pencil, Trash2, Loader2, Upload, Download, Swords } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast } from '@/components/ui'
import styles from '@/components/settings/Settings.module.css'

export function AgentSkillsTab() {
  const { userId } = useProject()
  const { alertError, alert: showAlert, confirm: showConfirm } = useAlertModal()
  const toast = useToast()

  const [attackSkills, setAttackSkills] = useState<{ id: string; name: string; description?: string | null; createdAt: string }[]>([])
  const [skillsLoading, setSkillsLoading] = useState(true)
  const [skillNameModal, setSkillNameModal] = useState(false)
  const [pendingSkillContent, setPendingSkillContent] = useState('')
  const [pendingSkillName, setPendingSkillName] = useState('')
  const [pendingSkillDescription, setPendingSkillDescription] = useState('')
  const [skillUploading, setSkillUploading] = useState(false)
  const [editDescModal, setEditDescModal] = useState(false)
  const [editingSkillId, setEditingSkillId] = useState('')
  const [editingSkillDescription, setEditingSkillDescription] = useState('')
  const [editDescSaving, setEditDescSaving] = useState(false)
  const [importingAgentSkills, setImportingAgentSkills] = useState(false)

  const fetchSkills = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills`)
      if (resp.ok) setAttackSkills(await resp.json())
    } catch (err) {
      console.error('Failed to fetch attack skills:', err)
    } finally {
      setSkillsLoading(false)
    }
  }, [userId])

  useEffect(() => { fetchSkills() }, [fetchSkills])

  const handleSkillUpload = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file || !userId) return

    const reader = new FileReader()
    reader.onload = () => {
      setPendingSkillContent(reader.result as string)
      setPendingSkillName(file.name.replace(/\.md$/i, ''))
      setSkillNameModal(true)
    }
    reader.readAsText(file)
    e.target.value = ''
  }, [userId])

  const confirmSkillUpload = useCallback(async () => {
    if (!userId || !pendingSkillName.trim()) return
    setSkillUploading(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: pendingSkillName.trim(), description: pendingSkillDescription.trim() || null, content: pendingSkillContent }),
      })
      if (resp.ok) {
        fetchSkills()
        setSkillNameModal(false)
        setPendingSkillContent('')
        setPendingSkillName('')
        setPendingSkillDescription('')
        toast.success('Attack skill uploaded')
      } else {
        const err = await resp.json()
        alertError(err.error || 'Failed to upload skill')
      }
    } catch (err) {
      console.error('Failed to upload skill:', err)
      toast.error('Failed to upload skill')
    } finally {
      setSkillUploading(false)
    }
  }, [userId, pendingSkillName, pendingSkillDescription, pendingSkillContent, fetchSkills])

  const downloadSkill = useCallback(async (skillId: string, skillName: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skillId}`)
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
      console.error('Failed to download skill:', err)
    }
  }, [userId])

  const deleteSkill = useCallback(async (skillId: string) => {
    if (!userId || !(await showConfirm('Delete this skill? It will be removed from all projects.'))) return
    try {
      await fetch(`/api/users/${userId}/attack-skills/${skillId}`, { method: 'DELETE' })
      fetchSkills()
      toast.success('Attack skill deleted')
    } catch (err) {
      console.error('Failed to delete skill:', err)
      toast.error('Failed to delete skill')
    }
  }, [userId, fetchSkills])

  const openEditDescription = useCallback(async (skillId: string) => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${skillId}`)
      if (resp.ok) {
        const skill = await resp.json()
        setEditingSkillId(skillId)
        setEditingSkillDescription(skill.description || '')
        setEditDescModal(true)
      }
    } catch (err) {
      console.error('Failed to fetch skill:', err)
    }
  }, [userId])

  const saveEditDescription = useCallback(async () => {
    if (!userId || !editingSkillId) return
    setEditDescSaving(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/${editingSkillId}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ description: editingSkillDescription.trim() || null }),
      })
      if (resp.ok) {
        fetchSkills()
        setEditDescModal(false)
        setEditingSkillId('')
        setEditingSkillDescription('')
        toast.success('Skill description updated')
      } else {
        const err = await resp.json()
        alertError(err.error || 'Failed to update description')
      }
    } catch (err) {
      console.error('Failed to update skill description:', err)
      toast.error('Failed to update description')
    } finally {
      setEditDescSaving(false)
    }
  }, [userId, editingSkillId, editingSkillDescription, fetchSkills])

  const importCommunityAgentSkills = useCallback(async () => {
    if (!userId) return
    setImportingAgentSkills(true)
    try {
      const resp = await fetch(`/api/users/${userId}/attack-skills/import-community`, { method: 'POST' })
      const data = await resp.json()
      if (resp.ok) {
        fetchSkills()
        showAlert(data.message || `Imported ${data.imported ?? 0} community skill(s).`)
      } else {
        alertError(data.error || 'Failed to import community skills')
      }
    } catch (err) {
      console.error('Failed to import community skills:', err)
    } finally {
      setImportingAgentSkills(false)
    }
  }, [userId, fetchSkills])

  return (
    <>
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
            <Swords size={16} /> Agent Skills
          </h2>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              className="secondaryButton"
              onClick={importCommunityAgentSkills}
              disabled={importingAgentSkills}
            >
              {importingAgentSkills ? <Loader2 size={14} className={styles.spin} /> : <Download size={14} />}
              Import from Community
            </button>
            <label className="primaryButton" style={{ cursor: 'pointer' }}>
              <Upload size={14} /> Upload Skill
              <input
                type="file"
                accept=".md"
                style={{ display: 'none' }}
                onChange={handleSkillUpload}
              />
            </label>
          </div>
        </div>
        <p className={styles.sectionHint}>
          Upload .md files defining custom attack skill workflows. Skills become available as toggles in all project settings.
        </p>

        {skillsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : attackSkills.length === 0 ? (
          <div className={styles.emptyState}>No custom skills uploaded yet. Upload a .md file to get started.</div>
        ) : (
          <div className={styles.providerList}>
            {attackSkills.map(skill => (
              <div key={skill.id} className={styles.providerCard}>
                <span className={styles.providerIcon}><Swords size={16} /></span>
                <div className={styles.providerInfo}>
                  <div className={styles.providerName}>{skill.name}</div>
                  <div className={styles.providerMeta}>
                    {skill.description || <span style={{ opacity: 0.5, fontStyle: 'italic' }}>No description</span>}
                  </div>
                  <div className={styles.providerMeta}>
                    Uploaded {new Date(skill.createdAt).toLocaleDateString()}
                  </div>
                </div>
                <div className={styles.providerActions}>
                  <button className="iconButton" title="Edit description" onClick={() => openEditDescription(skill.id)}>
                    <Pencil size={14} />
                  </button>
                  <button className="iconButton" title="Download" onClick={() => downloadSkill(skill.id, skill.name)}>
                    <Download size={14} />
                  </button>
                  <button className="iconButton" title="Delete" onClick={() => deleteSkill(skill.id)}>
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Skill upload modal */}
      <Modal
        isOpen={skillNameModal}
        onClose={() => { setSkillNameModal(false); setPendingSkillContent(''); setPendingSkillName(''); setPendingSkillDescription('') }}
        title="Upload Attack Skill"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setSkillNameModal(false); setPendingSkillContent(''); setPendingSkillName(''); setPendingSkillDescription('') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={!pendingSkillName.trim() || skillUploading}
              onClick={confirmSkillUpload}
            >
              {skillUploading ? <Loader2 size={14} className={styles.spin} /> : <Upload size={14} />}
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
            value={pendingSkillName}
            onChange={(e) => setPendingSkillName(e.target.value)}
            placeholder="e.g. SQL Injection Workflow"
            autoFocus
          />
          <span className="formHint">
            This name appears in project settings and classification badges.
          </span>
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel">Description</label>
          <textarea
            className="textInput"
            rows={3}
            value={pendingSkillDescription}
            onChange={(e) => setPendingSkillDescription(e.target.value)}
            placeholder="e.g. SQL injection testing against web app parameters using sqlmap"
            maxLength={500}
          />
          <span className="formHint">
            Helps the agent understand when to use this skill. Without a description, the first 500 characters of the markdown are used instead &mdash; a good description improves classification accuracy.
          </span>
        </div>
      </Modal>

      {/* Edit description modal */}
      <Modal
        isOpen={editDescModal}
        onClose={() => { setEditDescModal(false); setEditingSkillId(''); setEditingSkillDescription('') }}
        title="Edit Skill Description"
        size="small"
        footer={
          <>
            <button
              className="secondaryButton"
              onClick={() => { setEditDescModal(false); setEditingSkillId(''); setEditingSkillDescription('') }}
            >
              Cancel
            </button>
            <button
              className="primaryButton"
              disabled={editDescSaving}
              onClick={saveEditDescription}
            >
              {editDescSaving ? <Loader2 size={14} className={styles.spin} /> : <Pencil size={14} />}
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
            value={editingSkillDescription}
            onChange={(e) => setEditingSkillDescription(e.target.value)}
            placeholder="e.g. SQL injection testing against web app parameters using sqlmap"
            maxLength={500}
            autoFocus
          />
          <span className="formHint">
            Helps the agent understand when to use this skill. Without a description, the first 500 characters of the markdown are used instead &mdash; a good description improves classification accuracy.
          </span>
        </div>
      </Modal>
    </>
  )
}

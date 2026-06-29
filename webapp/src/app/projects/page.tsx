'use client'

import { useState, useEffect, useRef } from 'react'
import { useRouter } from 'next/navigation'
import { Plus, FolderOpen, Users, RefreshCw, Trash2, Upload, Zap, Loader2 } from 'lucide-react'
import Link from 'next/link'
import { useProjects, useDeleteProject } from '@/hooks/useProjects'
import { useUsers, useCreateUser, useDeleteUser } from '@/hooks/useUsers'
import { useProject } from '@/providers/ProjectProvider'
import { ProjectCard } from '@/components/projects/ProjectCard'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { ImportModal } from './ImportModal'
import styles from './page.module.css'

export default function ProjectsPage() {
  const router = useRouter()
  const { userId, setUserId, setCurrentProject } = useProject()
  const { alertError, dangerConfirm } = useAlertModal()
  const toast = useToast()
  const [showUserModal, setShowUserModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)
  const [showQuickCreate, setShowQuickCreate] = useState(false)
  const [newUserName, setNewUserName] = useState('')
  const [newUserEmail, setNewUserEmail] = useState('')

  // Quick Create state
  const [qcName, setQcName] = useState('')
  const [qcDomain, setQcDomain] = useState('')
  const [qcSubmitting, setQcSubmitting] = useState(false)
  const [qcStartingRecon, setQcStartingRecon] = useState(false)

  const { data: users, isLoading: usersLoading } = useUsers()
  const { data: projects, isLoading: projectsLoading, refetch } = useProjects(userId || undefined)
  const deleteProjectMutation = useDeleteProject()
  const createUserMutation = useCreateUser()
  const deleteUserMutation = useDeleteUser()
  const hasAutoSelected = useRef(false)

  useEffect(() => {
    if (!users) return
    if (userId && !users.find(u => u.id === userId)) {
      setUserId(users.length > 0 ? users[0].id : null)
      setCurrentProject(null)
    } else if (!hasAutoSelected.current && !userId && users.length > 0) {
      setUserId(users[0].id)
      hasAutoSelected.current = true
    }
  }, [userId, users, setUserId, setCurrentProject])

  const handleSelectProject = (project: { id: string; name: string; targetDomain: string }) => {
    setCurrentProject({
      id: project.id,
      name: project.name,
      targetDomain: project.targetDomain,
      createdAt: '',
      updatedAt: ''
    })
    router.push(`/graph?project=${project.id}`)
  }

  const handleDeleteProject = async (projectId: string) => {
    if (await dangerConfirm('Are you sure you want to delete this project? This action cannot be undone.')) {
      await deleteProjectMutation.mutateAsync(projectId)
      toast.success('Project deleted')
    }
  }

  const handleStartScan = async (projectId: string) => {
    try {
      const res = await fetch(`/api/recon/${projectId}/start`, { method: 'POST' })
      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        const err = data.error || ''
        if (res.status === 0 || err.includes('fetch failed') || err.includes('ECONNREFUSED')) {
          alertError('Recon orchestrator is not running. Start it with: docker compose up -d recon-orchestrator')
        } else {
          alertError(err || 'Failed to start recon')
        }
        return
      }
      toast.success('Recon pipeline started')
      router.push(`/graph?project=${projectId}&autostart=true`)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to start recon'
      if (msg.includes('fetch') || msg.includes('Failed to fetch')) {
        alertError('Cannot reach recon orchestrator. Ensure it is running: docker compose up -d recon-orchestrator')
      } else {
        alertError(msg)
      }
    }
  }

  // Quick Create: create project via API
  const handleQuickCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!userId) {
      alertError('Select a user first')
      return
    }
    if (!qcName.trim()) {
      alertError('Project name is required')
      return
    }
    if (!qcDomain.trim()) {
      alertError('Target domain is required')
      return
    }

    setQcSubmitting(true)
    try {
      const res = await fetch('/api/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId,
          name: qcName.trim(),
          targetDomain: qcDomain.trim(),
        }),
      })

      if (!res.ok) {
        const data = await res.json().catch(() => ({}))
        alertError(data.error || 'Failed to create project')
        setQcSubmitting(false)
        return
      }

      const project = await res.json()
      toast.success('Project created')

      // Set current project and optionally start recon
      setCurrentProject({
        id: project.id,
        name: project.name,
        targetDomain: project.targetDomain,
        createdAt: project.createdAt,
        updatedAt: project.updatedAt,
      })

      // Auto-start recon
      setQcStartingRecon(true)
      try {
        const reconRes = await fetch(`/api/recon/${project.id}/start`, { method: 'POST' })
        if (reconRes.ok) {
          toast.success('Recon pipeline started')
          router.push(`/graph?project=${project.id}&openlogs=recon`)
          return
        }
        const reconData = await reconRes.json().catch(() => ({}))
        const reconErr = reconData.error || ''
        if (reconRes.status === 0 || reconErr.includes('fetch failed') || reconErr.includes('ECONNREFUSED')) {
          toast.error('Project created, but recon orchestrator is not running')
        } else {
          toast.error(`Project created, but recon failed: ${reconErr}`)
        }
      } catch {
        toast.error('Project created, but could not reach recon orchestrator')
      }

      // Navigate to graph — recon logs will open if it started, graph view otherwise
      router.push(`/graph?project=${project.id}`)
    } catch (err) {
      alertError(err instanceof Error ? err.message : 'Failed to create project')
      setQcSubmitting(false)
      setQcStartingRecon(false)
    } finally {
      if (!qcStartingRecon) setQcSubmitting(false)
    }
  }

  const handleCreateUser = async (e: React.FormEvent) => {
    e.preventDefault()
    try {
      const user = await createUserMutation.mutateAsync({
        name: newUserName,
        email: newUserEmail
      })
      setUserId(user.id)
      setShowUserModal(false)
      setNewUserName('')
      setNewUserEmail('')
      toast.success('User created')
    } catch (error) {
      alertError(error instanceof Error ? error.message : 'Failed to create user')
    }
  }

  const handleDeleteUser = async () => {
    if (!userId) return
    const selectedUser = users?.find(u => u.id === userId)
    const projectCount = selectedUser?._count?.projects ?? 0
    const warning = projectCount > 0
      ? `This will permanently delete user "${selectedUser?.name}" and their ${projectCount} project(s). This action cannot be undone.`
      : `Are you sure you want to delete user "${selectedUser?.name}"? This action cannot be undone.`
    if (await dangerConfirm(warning)) {
      try {
        await deleteUserMutation.mutateAsync(userId)
        setUserId(null)
        setCurrentProject(null)
        toast.success('User deleted')
      } catch (error) {
        alertError(error instanceof Error ? error.message : 'Failed to delete user')
      }
    }
  }

  const isLoading = usersLoading || projectsLoading
  const isCreating = qcSubmitting || qcStartingRecon

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div className={styles.headerLeft}>
          <FolderOpen size={20} />
          <h1 className={styles.title}>Projects</h1>
          <WikiInfoButton target="projects" title="Open Creating a Project wiki page" />
        </div>
        <div className={styles.headerActions}>
          <button
            className="iconButton"
            onClick={() => refetch()}
            title="Refresh"
          >
            <RefreshCw size={14} />
          </button>
          {userId && (
            <>
              <button
                className={styles.quickCreateBtn}
                onClick={() => {
                  setQcName('')
                  setQcDomain('')
                  setShowQuickCreate(true)
                }}
                title="Quickly create a project with just a name and domain"
              >
                <Zap size={14} />
                Quick Create
              </button>
              <button
                className="secondaryButton"
                onClick={() => setShowImportModal(true)}
                title="Import project from backup"
              >
                <Upload size={14} />
                Import
              </button>
            </>
          )}
          {userId ? (
            <Link href="/projects/new" className="primaryButton">
              <Plus size={14} />
              New Project
            </Link>
          ) : (
            <button className="primaryButton" disabled>
              <Plus size={14} />
              New Project
            </button>
          )}
        </div>
      </div>

      <div className={styles.userSelector}>
        <div className={styles.userSelectorLabel}>
          <Users size={14} />
          <span>User:</span>
        </div>
        <select
          className="select"
          value={userId || ''}
          onChange={(e) => setUserId(e.target.value || null)}
        >
          <option value="">Select a user</option>
          {users?.map((user) => (
            <option key={user.id} value={user.id}>
              {user.name} ({user.email})
            </option>
          ))}
        </select>
        <button
          className="secondaryButton"
          onClick={() => setShowUserModal(true)}
        >
          <Plus size={12} />
          New User
        </button>
        {userId && (
          <button
            className="iconButton"
            onClick={handleDeleteUser}
            disabled={deleteUserMutation.isPending}
            title="Delete selected user"
          >
            <Trash2 size={14} />
          </button>
        )}
      </div>

      {isLoading ? (
        <div className={styles.skeletonGrid}>
          {[1, 2, 3].map(i => (
            <div key={i} className={styles.skeletonCard}>
              <div className={styles.skeletonLine} />
              <div className={styles.skeletonLine} />
              <div className={styles.skeletonLine} />
              <div className={styles.skeletonActions}>
                <div className={styles.skeletonBtn} />
                <div className={styles.skeletonBtn} />
              </div>
            </div>
          ))}
        </div>
      ) : projects && projects.length > 0 ? (
        <div className={styles.grid}>
          {projects.map((project) => (
            <ProjectCard
              key={project.id}
              id={project.id}
              name={project.name}
              targetDomain={project.targetDomain}
              description={project.description}
              createdAt={project.createdAt}
              onSelect={() => handleSelectProject(project)}
              onDelete={() => handleDeleteProject(project.id)}
              onStartScan={() => handleStartScan(project.id)}
            />
          ))}
        </div>
      ) : (
        <div className={styles.empty}>
          <FolderOpen size={48} />
          <h2>No Projects Yet</h2>
          <p>Create your first project to get started with reconnaissance.</p>
          <div className={styles.emptyActions}>
            {userId ? (
              <>
                <button
                  className={styles.quickCreateBtn}
                  onClick={() => {
                    setQcName('')
                    setQcDomain('')
                    setShowQuickCreate(true)
                  }}
                >
                  <Zap size={14} />
                  Quick Create
                </button>
                <Link href="/projects/new" className="primaryButton">
                  <Plus size={14} />
                  Full Setup
                </Link>
              </>
            ) : (
              <button className="primaryButton" disabled>
                <Plus size={14} />
                Create Project
              </button>
            )}
          </div>
        </div>
      )}

      {/* ─── Quick Create Modal ─── */}
      {showQuickCreate && (
        <div className={styles.modalOverlay} onClick={() => !isCreating && setShowQuickCreate(false)}>
          <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
            {isCreating ? (
              <div className={styles.creatingStatus}>
                <Loader2 size={24} className={styles.creatingSpinner} />
                <p>{qcStartingRecon ? 'Starting recon pipeline...' : 'Creating project...'}</p>
              </div>
            ) : (
              <>
                <h2 className={styles.modalTitle}>
                  <Zap size={16} style={{ marginRight: 'var(--space-1-5)', verticalAlign: 'middle' }} />
                  Quick Create Project
                </h2>
                <p className={styles.modalSubtitle}>
                  Minimal setup — sensible defaults applied. Use <strong>New Project</strong> for full configuration.
                </p>
                <form onSubmit={handleQuickCreate}>
                  <div className="formGroup">
                    <label className="formLabel formLabelRequired">Project Name</label>
                    <input
                      type="text"
                      className="textInput"
                      value={qcName}
                      onChange={(e) => setQcName(e.target.value)}
                      placeholder="e.g., Acme Corp Pentest"
                      autoFocus
                      required
                    />
                  </div>
                  <div className="formGroup">
                    <label className="formLabel formLabelRequired">Target Domain</label>
                    <input
                      type="text"
                      className="textInput"
                      value={qcDomain}
                      onChange={(e) => setQcDomain(e.target.value)}
                      placeholder="e.g., example.com"
                      required
                    />
                  </div>
                  <div className={styles.quickCreateInfo}>
                    <strong>Defaults applied:</strong> Full scan profile, all recon modules enabled,
                    nuclei critical+high+medium, max 100 iterations, standard stealth mode off.
                  </div>
                  <div className={styles.modalActions}>
                    <button
                      type="button"
                      className="secondaryButton"
                      onClick={() => setShowQuickCreate(false)}
                      disabled={isCreating}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="primaryButton"
                      disabled={isCreating || !userId}
                    >
                      <Zap size={14} />
                      Create & Scan
                    </button>
                  </div>
                </form>
              </>
            )}
          </div>
        </div>
      )}

      {userId && (
        <ImportModal
          isOpen={showImportModal}
          userId={userId}
          onClose={() => setShowImportModal(false)}
          onSuccess={() => refetch()}
        />
      )}

      {showUserModal && (
        <div className={styles.modalOverlay} onClick={() => setShowUserModal(false)}>
          <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
            <h2 className={styles.modalTitle}>Create New User</h2>
            <form onSubmit={handleCreateUser}>
              <div className="formGroup">
                <label className="formLabel formLabelRequired">Name</label>
                <input
                  type="text"
                  className="textInput"
                  value={newUserName}
                  onChange={(e) => setNewUserName(e.target.value)}
                  placeholder="Enter user name"
                  required
                />
              </div>
              <div className="formGroup">
                <label className="formLabel formLabelRequired">Email</label>
                <input
                  type="email"
                  className="textInput"
                  value={newUserEmail}
                  onChange={(e) => setNewUserEmail(e.target.value)}
                  placeholder="Enter email address"
                  required
                />
              </div>
              <div className={styles.modalActions}>
                <button
                  type="button"
                  className="secondaryButton"
                  onClick={() => setShowUserModal(false)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="primaryButton"
                  disabled={createUserMutation.isPending}
                >
                  {createUserMutation.isPending ? 'Creating...' : 'Create User'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { useSearchParams } from 'next/navigation'
import { Plus, Pencil, Trash2, Loader2, Swords, Info, BookOpen, Server } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { LlmProviderForm } from '@/components/settings/LlmProviderForm'
import McpServersTab from '@/components/settings/mcp/McpServersTab'
import type { ProviderData } from '@/components/settings/LlmProviderForm'
import { TradecraftResourceForm } from '@/components/settings/TradecraftResourceForm'
import { TradecraftResourceList } from '@/components/settings/TradecraftResourceList'
import { PROVIDER_TYPES } from '@/lib/llmProviderPresets'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { AgentSkillsTab } from '@/components/settings/tabs/AgentSkillsTab'
import { ChatSkillsTab } from '@/components/settings/tabs/ChatSkillsTab'
import { ApiKeysTab } from '@/components/settings/tabs/ApiKeysTab'
import { SystemSection } from '@/components/settings/SystemSection'
import styles from '@/components/settings/Settings.module.css'

function getProviderIconComponent(providerType: string) {
  return PROVIDER_TYPES.find(p => p.id === providerType)?.Icon ?? null
}

function getProviderLabel(providerType: string): string {
  return PROVIDER_TYPES.find(p => p.id === providerType)?.name || providerType
}

export default function SettingsPage() {
  const { userId } = useProject()
  const { confirm: showConfirm } = useAlertModal()
  const toast = useToast()

  // LLM Providers
  const [providers, setProviders] = useState<ProviderData[]>([])
  const [providersLoading, setProvidersLoading] = useState(true)
  const [showProviderForm, setShowProviderForm] = useState(false)
  const [editingProvider, setEditingProvider] = useState<ProviderData | null>(null)

  // Tradecraft Resources state
  type TcResource = import('@/components/settings/TradecraftResourceForm').TradecraftResource & {
    crawlStoppedBecause?: string
    crawlStats?: { pages_fetched?: number; llm_calls?: number; elapsed_sec?: number }
    sitemap?: { nav?: unknown[]; tree?: unknown[]; pages?: unknown[]; links?: unknown[] }
  }
  const [tcResources, setTcResources] = useState<TcResource[]>([])
  const [tcLoading, setTcLoading] = useState(false)
  const [tcShowForm, setTcShowForm] = useState(false)
  const [tcEditing, setTcEditing] = useState<TcResource | null>(null)
  const [tcRefreshingId, setTcRefreshingId] = useState<string | null>(null)
  const tcPollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const searchParams = useSearchParams()
  const validTabs = ['providers', 'skills', 'chat-skills', 'tradecraft', 'keys', 'mcp', 'system']
  const initialTab = searchParams.get('tab') || 'providers'
  const [activeTab, setActiveTab] = useState(validTabs.includes(initialTab) ? initialTab : 'providers')

  const fetchProviders = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/llm-providers`)
      if (resp.ok) setProviders(await resp.json())
    } catch (err) {
      console.error('Failed to fetch providers:', err)
    } finally {
      setProvidersLoading(false)
    }
  }, [userId])

  const fetchTcResources = useCallback(async () => {
    if (!userId) return
    setTcLoading(true)
    try {
      const r = await fetch(`/api/users/${userId}/tradecraft-resources`)
      if (r.ok) setTcResources(await r.json())
    } catch (e) { console.error('fetchTcResources', e) }
    finally { setTcLoading(false) }
  }, [userId])

  useEffect(() => { fetchProviders() }, [fetchProviders])

  useEffect(() => {
    if (activeTab === 'tradecraft' && userId) {
      fetchTcResources()
    }
  }, [activeTab, userId, fetchTcResources])

  // Light polling while a resource has not yet been verified (lastVerifiedAt null)
  useEffect(() => {
    if (activeTab !== 'tradecraft' || !userId) {
      if (tcPollingRef.current) { clearInterval(tcPollingRef.current); tcPollingRef.current = null }
      return
    }
    const anyPending = tcResources.some(r => !r.lastVerifiedAt)
    if (anyPending && !tcPollingRef.current) {
      tcPollingRef.current = setInterval(fetchTcResources, 5000)
    } else if (!anyPending && tcPollingRef.current) {
      clearInterval(tcPollingRef.current); tcPollingRef.current = null
    }
    return () => {
      if (tcPollingRef.current) { clearInterval(tcPollingRef.current); tcPollingRef.current = null }
    }
  }, [activeTab, userId, tcResources, fetchTcResources])

  const deleteProvider = useCallback(async (providerId: string) => {
    if (!userId || !(await showConfirm('Delete this provider? Models from it will no longer be available.'))) return
    try {
      await fetch(`/api/users/${userId}/llm-providers/${providerId}`, { method: 'DELETE' })
      fetchProviders()
      toast.success('Provider deleted')
    } catch (err) {
      console.error('Failed to delete provider:', err)
      toast.error('Failed to delete provider')
    }
  }, [userId, fetchProviders])

  const tcHandleSave = useCallback(() => {
    setTcShowForm(false); setTcEditing(null); fetchTcResources(); toast.success('Saved')
  }, [fetchTcResources, toast])

  const tcHandleCancel = useCallback(() => { setTcShowForm(false); setTcEditing(null) }, [])

  const tcHandleDelete = useCallback(async (r: TcResource) => {
    if (!userId || !r.id) return
    const ok = await showConfirm(
      `Delete "${r.name}"? This removes the catalog entry and disk cache.`,
      'Delete tradecraft resource',
    )
    if (!ok) return
    try {
      const resp = await fetch(`/api/users/${userId}/tradecraft-resources/${r.id}`, { method: 'DELETE' })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      toast.success('Deleted')
      fetchTcResources()
    } catch (e) { toast.error(`Delete failed: ${e instanceof Error ? e.message : String(e)}`) }
  }, [userId, showConfirm, toast, fetchTcResources])

  const tcHandleRefresh = useCallback(async (r: TcResource) => {
    if (!userId || !r.id) return
    setTcRefreshingId(r.id)
    try {
      const resp = await fetch(`/api/users/${userId}/tradecraft-resources/${r.id}/refresh`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
      })
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}))
        throw new Error(data.error || `HTTP ${resp.status}`)
      }
      toast.success('Refreshed')
      fetchTcResources()
    } catch (e) { toast.error(`Refresh failed: ${e instanceof Error ? e.message : String(e)}`) }
    finally { setTcRefreshingId(null) }
  }, [userId, toast, fetchTcResources])

  const tcHandleToggleEnabled = useCallback(async (r: TcResource, next: boolean) => {
    if (!userId || !r.id) return
    setTcResources(prev => prev.map(x => x.id === r.id ? { ...x, enabled: next } : x))
    try {
      const resp = await fetch(`/api/users/${userId}/tradecraft-resources/${r.id}`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: next }),
      })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
    } catch (e) {
      toast.error(`Toggle failed: ${e instanceof Error ? e.message : String(e)}`)
      fetchTcResources()
    }
  }, [userId, toast, fetchTcResources])

  if (!userId) {
    return (
      <div className={styles.page}>
        <h1 className={styles.pageTitle} style={{ display: 'inline-flex', alignItems: 'center', gap: '12px' }}>
          <span>Global Settings <span style={{ fontSize: '0.55em', fontWeight: 400, opacity: 0.5 }}>(User-Scoped)</span></span>
          <WikiInfoButton target="settings" title="Open Global Settings wiki page" />
        </h1>
        <div className={styles.emptyState}>Select a user to configure settings.</div>
      </div>
    )
  }

  return (
    <div className={styles.page}>
      <h1 className={styles.pageTitle}>Global Settings <span style={{ fontSize: '0.55em', fontWeight: 400, opacity: 0.5 }}>(User-Scoped)</span></h1>
      <p style={{ color: 'var(--text-secondary)', fontSize: '13px', margin: '0 0 var(--space-4)' }}>
        Personal configuration for the current user. These settings apply across all projects.
      </p>

      <div className={styles.tabBar}>
        <button className={`${styles.tab} ${activeTab === 'providers' ? styles.tabActive : ''}`} onClick={() => setActiveTab('providers')}>
          LLM Providers
        </button>
        <button className={`${styles.tab} ${activeTab === 'skills' ? styles.tabActive : ''}`} onClick={() => setActiveTab('skills')}>
          <Swords size={14} /> Agent Skills
        </button>
        <button className={`${styles.tab} ${activeTab === 'chat-skills' ? styles.tabActive : ''}`} onClick={() => setActiveTab('chat-skills')}>
          <BookOpen size={14} /> Chat Skills
        </button>
        <button className={`${styles.tab} ${activeTab === 'tradecraft' ? styles.tabActive : ''}`} onClick={() => setActiveTab('tradecraft')}>
          <BookOpen size={14} /> Tradecraft
        </button>
        <button className={`${styles.tab} ${activeTab === 'keys' ? styles.tabActive : ''}`} onClick={() => setActiveTab('keys')}>
          API Keys & Tunneling
        </button>
        <button className={`${styles.tab} ${activeTab === 'mcp' ? styles.tabActive : ''}`} onClick={() => setActiveTab('mcp')}>
          <Server size={14} /> MCP Tool Plugins
        </button>
        <button className={`${styles.tab} ${activeTab === 'system' ? styles.tabActive : ''}`} onClick={() => setActiveTab('system')}>
          <Info size={14} /> System
        </button>
      </div>

      {/* Tab: LLM Providers */}
      {activeTab === 'providers' && <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
            <span>LLM Providers</span>
            <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/AI-Model-Providers" title="Open AI Model Providers wiki page" />
          </h2>
          {!showProviderForm && !editingProvider && (
            <button className="primaryButton" onClick={() => setShowProviderForm(true)}>
              <Plus size={14} /> Add Provider
            </button>
          )}
        </div>
        <p className={styles.sectionHint}>
          Models from all providers appear in every project&apos;s LLM selector. Key-based providers auto-discover available models.
        </p>

        {(showProviderForm || editingProvider) && (
          <LlmProviderForm
            userId={userId}
            provider={editingProvider}
            existingProviderTypes={providers.map(p => p.providerType)}
            onSave={() => {
              setShowProviderForm(false)
              setEditingProvider(null)
              fetchProviders()
            }}
            onCancel={() => {
              setShowProviderForm(false)
              setEditingProvider(null)
            }}
          />
        )}

        {!showProviderForm && !editingProvider && (
          providersLoading ? (
            <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
          ) : providers.length === 0 ? (
            <div className={styles.emptyState}>No providers configured. Add one to get started.</div>
          ) : (
            <div className={styles.providerList}>
              {providers.map((p: ProviderData) => {
                const Icon = getProviderIconComponent(p.providerType)
                return (
                <div key={p.id} className={styles.providerCard}>
                  <span className={styles.providerIcon} aria-label={getProviderLabel(p.providerType)}>
                    {Icon ? <Icon size={28} /> : null}
                  </span>
                  <div className={styles.providerInfo}>
                    <div className={styles.providerName}>{p.name}</div>
                    <div className={styles.providerMeta}>
                      {getProviderLabel(p.providerType)}
                      {p.providerType === 'openai_compatible' && p.modelIdentifier && ` — ${p.modelIdentifier}`}
                    </div>
                  </div>
                  <div className={styles.providerActions}>
                    <button className="iconButton" title="Edit" onClick={() => setEditingProvider(p)}>
                      <Pencil size={14} />
                    </button>
                    <button className="iconButton" title="Delete" onClick={() => deleteProvider(p.id!)}>
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
                )
              })}
            </div>
          )
        )}
      </div>}

      {/* Tab: Agent Skills */}
      {activeTab === 'skills' && <AgentSkillsTab />}

      {/* Tab: Chat Skills */}
      {activeTab === 'chat-skills' && <ChatSkillsTab />}

      {/* Tab: Tradecraft Resources */}
      {activeTab === 'tradecraft' && <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle}>
            Tradecraft Resources
            <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Tradecraft-Lookup" title="Open Tradecraft Lookup wiki page" />
          </h2>
          {!tcShowForm && !tcEditing && (
            <button className="primaryButton" onClick={() => setTcShowForm(true)}>
              <Plus size={14} /> Add Resource
            </button>
          )}
        </div>
        <p className={styles.sectionHint}>
          Curated knowledge sites the agent consults during exploitation
          (HackTricks, PayloadsAllTheThings, CVE PoC repos, ...). On add, the
          agent fetches the homepage, builds a sitemap, and writes a short
          summary that becomes the tool&apos;s catalog entry. The agent only sees
          enabled resources.
        </p>
        {(tcShowForm || tcEditing) && (
          <TradecraftResourceForm
            userId={userId!}
            resource={tcEditing}
            onSave={tcHandleSave}
            onCancel={tcHandleCancel}
          />
        )}
        <TradecraftResourceList
          resources={tcResources}
          loading={tcLoading}
          refreshingId={tcRefreshingId}
          onEdit={(r) => setTcEditing(r)}
          onDelete={tcHandleDelete}
          onRefresh={tcHandleRefresh}
          onToggleEnabled={tcHandleToggleEnabled}
        />
      </div>}

      {/* Tab: API Keys & Tunneling */}
      {activeTab === 'keys' && <ApiKeysTab />}

      {/* Tab: MCP */}
      {activeTab === 'mcp' && userId && <McpServersTab userId={userId} />}

      {/* Tab: System */}
      {activeTab === 'system' && <SystemSection />}
    </div>
  )
}

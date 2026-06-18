'use client'

import { useState, useCallback, useEffect, useRef } from 'react'
import { Loader2, Upload, Download, RotateCw } from 'lucide-react'
import { useProject } from '@/providers/ProjectProvider'
import { Modal } from '@/components/ui/Modal/Modal'
import { useAlertModal, useToast, WikiInfoButton } from '@/components/ui'
import { SecretField } from '@/components/settings/SecretField'
import type { RotationInfo } from '@/components/settings/SecretField'
import styles from '@/components/settings/Settings.module.css'
import { buildTemplate, templateToJson, validateAndParse, isValidationError } from '@/lib/apiKeysTemplate'
import type { ParsedImport } from '@/lib/apiKeysTemplate'

interface UserSettings {
  githubAccessToken: string
  tavilyApiKey: string
  shodanApiKey: string
  serpApiKey: string
  nvdApiKey: string
  vulnersApiKey: string
  urlscanApiKey: string
  censysApiToken: string
  censysOrgId: string
  fofaApiKey: string
  otxApiKey: string
  netlasApiKey: string
  virusTotalApiKey: string
  zoomEyeApiKey: string
  criminalIpApiKey: string
  quakeApiKey: string
  hunterApiKey: string
  publicWwwApiKey: string
  hunterHowApiKey: string
  googleApiKey: string
  googleApiCx: string
  onypheApiKey: string
  driftnetApiKey: string
  wpscanApiToken: string
  pdcpApiKey: string
  ngrokAuthtoken: string
  chiselServerUrl: string
  chiselAuth: string
}

const EMPTY_SETTINGS: UserSettings = {
  githubAccessToken: '',
  tavilyApiKey: '',
  shodanApiKey: '',
  serpApiKey: '',
  nvdApiKey: '',
  vulnersApiKey: '',
  urlscanApiKey: '',
  censysApiToken: '',
  censysOrgId: '',
  fofaApiKey: '',
  otxApiKey: '',
  netlasApiKey: '',
  virusTotalApiKey: '',
  zoomEyeApiKey: '',
  criminalIpApiKey: '',
  quakeApiKey: '',
  hunterApiKey: '',
  publicWwwApiKey: '',
  hunterHowApiKey: '',
  googleApiKey: '',
  googleApiCx: '',
  onypheApiKey: '',
  driftnetApiKey: '',
  wpscanApiToken: '',
  pdcpApiKey: '',
  ngrokAuthtoken: '',
  chiselServerUrl: '',
  chiselAuth: '',
}

/** Maps settings field name → rotation tool name */
const TOOL_NAME_MAP: Record<string, string> = {
  tavilyApiKey: 'tavily',
  shodanApiKey: 'shodan',
  serpApiKey: 'serp',
  nvdApiKey: 'nvd',
  vulnersApiKey: 'vulners',
  urlscanApiKey: 'urlscan',
  fofaApiKey: 'fofa',
  otxApiKey: 'otx',
  netlasApiKey: 'netlas',
  virusTotalApiKey: 'virustotal',
  zoomEyeApiKey: 'zoomeye',
  criminalIpApiKey: 'criminalip',
  quakeApiKey: 'quake',
  hunterApiKey: 'hunter',
  publicWwwApiKey: 'publicwww',
  hunterHowApiKey: 'hunterhow',
  onypheApiKey: 'onyphe',
  driftnetApiKey: 'driftnet',
  wpscanApiToken: 'wpscan',
  pdcpApiKey: 'pdcp',
}

export function ApiKeysTab() {
  const { userId } = useProject()
  const { alertError, confirm: showConfirm } = useAlertModal()
  const toast = useToast()

  const [settings, setSettings] = useState<UserSettings>(EMPTY_SETTINGS)
  const [settingsLoading, setSettingsLoading] = useState(true)
  const [settingsDirty, setSettingsDirty] = useState(false)
  const [settingsSaving, setSettingsSaving] = useState(false)
  const [visibleFields, setVisibleFields] = useState<Record<string, boolean>>({})

  const [rotationConfigs, setRotationConfigs] = useState<Record<string, RotationInfo>>({})
  const [rotationModal, setRotationModal] = useState<string | null>(null)
  const [rotationDraft, setRotationDraft] = useState({ extraKeys: '', rotateEveryN: 10 })
  const [rotationDraftDirty, setRotationDraftDirty] = useState(false)

  const [pendingImport, setPendingImport] = useState<ParsedImport | null>(null)
  const importFileRef = useRef<HTMLInputElement>(null)

  const fetchSettings = useCallback(async () => {
    if (!userId) return
    try {
      const resp = await fetch(`/api/users/${userId}/settings`)
      if (resp.ok) {
        const data = await resp.json()
        setSettings({
          githubAccessToken: data.githubAccessToken || '',
          tavilyApiKey: data.tavilyApiKey || '',
          shodanApiKey: data.shodanApiKey || '',
          serpApiKey: data.serpApiKey || '',
          nvdApiKey: data.nvdApiKey || '',
          vulnersApiKey: data.vulnersApiKey || '',
          urlscanApiKey: data.urlscanApiKey || '',
          censysApiToken: data.censysApiToken || '',
          censysOrgId: data.censysOrgId || '',
          fofaApiKey: data.fofaApiKey || '',
          otxApiKey: data.otxApiKey || '',
          netlasApiKey: data.netlasApiKey || '',
          virusTotalApiKey: data.virusTotalApiKey || '',
          zoomEyeApiKey: data.zoomEyeApiKey || '',
          criminalIpApiKey: data.criminalIpApiKey || '',
          quakeApiKey: data.quakeApiKey || '',
          hunterApiKey: data.hunterApiKey || '',
          publicWwwApiKey: data.publicWwwApiKey || '',
          hunterHowApiKey: data.hunterHowApiKey || '',
          googleApiKey: data.googleApiKey || '',
          googleApiCx: data.googleApiCx || '',
          onypheApiKey: data.onypheApiKey || '',
          driftnetApiKey: data.driftnetApiKey || '',
          wpscanApiToken: data.wpscanApiToken || '',
          pdcpApiKey: data.pdcpApiKey || '',
          ngrokAuthtoken: data.ngrokAuthtoken || '',
          chiselServerUrl: data.chiselServerUrl || '',
          chiselAuth: data.chiselAuth || '',
        })
        if (data.rotationConfigs) {
          setRotationConfigs(data.rotationConfigs)
        }
      }
    } catch (err) {
      console.error('Failed to fetch settings:', err)
    } finally {
      setSettingsLoading(false)
    }
  }, [userId])

  useEffect(() => { fetchSettings() }, [fetchSettings])

  const saveSettings = useCallback(async () => {
    if (!userId) return
    setSettingsSaving(true)
    try {
      const rotPayload: Record<string, { extraKeys: string; rotateEveryN: number }> = {}
      for (const [, toolName] of Object.entries(TOOL_NAME_MAP)) {
        const info = rotationConfigs[toolName]
        if (info && (info as RotationInfo & { _extraKeys?: string })._extraKeys !== undefined) {
          rotPayload[toolName] = {
            extraKeys: (info as RotationInfo & { _extraKeys?: string })._extraKeys!,
            rotateEveryN: info.rotateEveryN,
          }
        } else if (info && info.extraKeyCount > 0) {
          rotPayload[toolName] = {
            extraKeys: '••••',
            rotateEveryN: info.rotateEveryN,
          }
        }
      }

      const resp = await fetch(`/api/users/${userId}/settings`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...settings, rotationConfigs: rotPayload }),
      })
      if (resp.ok) {
        const data = await resp.json()
        setSettings({
          githubAccessToken: data.githubAccessToken || '',
          tavilyApiKey: data.tavilyApiKey || '',
          shodanApiKey: data.shodanApiKey || '',
          serpApiKey: data.serpApiKey || '',
          nvdApiKey: data.nvdApiKey || '',
          vulnersApiKey: data.vulnersApiKey || '',
          urlscanApiKey: data.urlscanApiKey || '',
          censysApiToken: data.censysApiToken || '',
          censysOrgId: data.censysOrgId || '',
          fofaApiKey: data.fofaApiKey || '',
          otxApiKey: data.otxApiKey || '',
          netlasApiKey: data.netlasApiKey || '',
          virusTotalApiKey: data.virusTotalApiKey || '',
          zoomEyeApiKey: data.zoomEyeApiKey || '',
          criminalIpApiKey: data.criminalIpApiKey || '',
          quakeApiKey: data.quakeApiKey || '',
          hunterApiKey: data.hunterApiKey || '',
          publicWwwApiKey: data.publicWwwApiKey || '',
          hunterHowApiKey: data.hunterHowApiKey || '',
          googleApiKey: data.googleApiKey || '',
          googleApiCx: data.googleApiCx || '',
          onypheApiKey: data.onypheApiKey || '',
          driftnetApiKey: data.driftnetApiKey || '',
          wpscanApiToken: data.wpscanApiToken || '',
          pdcpApiKey: data.pdcpApiKey || '',
          ngrokAuthtoken: data.ngrokAuthtoken || '',
          chiselServerUrl: data.chiselServerUrl || '',
          chiselAuth: data.chiselAuth || '',
        })
        if (data.rotationConfigs) {
          setRotationConfigs(data.rotationConfigs)
        }
        setSettingsDirty(false)
        toast.success('Settings saved')
      }
    } catch (err) {
      console.error('Failed to save settings:', err)
      toast.error('Failed to save settings')
    } finally {
      setSettingsSaving(false)
    }
  }, [userId, settings, rotationConfigs])

  const updateSetting = useCallback(<K extends keyof UserSettings>(field: K, value: string) => {
    setSettings(prev => ({ ...prev, [field]: value }))
    setSettingsDirty(true)
  }, [])

  const toggleFieldVisibility = useCallback((field: string) => {
    setVisibleFields(prev => ({ ...prev, [field]: !prev[field] }))
  }, [])

  const openRotationModal = useCallback((settingsField: string) => {
    const toolName = TOOL_NAME_MAP[settingsField]
    if (!toolName) return
    const existing = rotationConfigs[toolName]
    setRotationModal(toolName)
    setRotationDraft({
      extraKeys: '',
      rotateEveryN: existing?.rotateEveryN ?? 10,
    })
    setRotationDraftDirty(false)
  }, [rotationConfigs])

  const closeRotationModal = useCallback(() => {
    setRotationModal(null)
    setRotationDraft({ extraKeys: '', rotateEveryN: 10 })
    setRotationDraftDirty(false)
  }, [])

  const saveRotationDraft = useCallback(() => {
    if (!rotationModal) return
    const existing = rotationConfigs[rotationModal]
    if (rotationDraftDirty) {
      const keys = rotationDraft.extraKeys.split('\n').filter(k => k.trim())
      setRotationConfigs(prev => ({
        ...prev,
        [rotationModal]: {
          extraKeyCount: keys.length,
          rotateEveryN: Math.max(1, rotationDraft.rotateEveryN),
          _extraKeys: rotationDraft.extraKeys,
        } as RotationInfo & { _extraKeys: string },
      }))
    } else {
      setRotationConfigs(prev => ({
        ...prev,
        [rotationModal]: {
          extraKeyCount: existing?.extraKeyCount ?? 0,
          rotateEveryN: Math.max(1, rotationDraft.rotateEveryN),
        },
      }))
    }
    setSettingsDirty(true)
    closeRotationModal()
  }, [rotationModal, rotationDraft, rotationDraftDirty, rotationConfigs, closeRotationModal])

  const clearRotationConfig = useCallback(() => {
    if (!rotationModal) return
    setRotationConfigs(prev => ({
      ...prev,
      [rotationModal]: {
        extraKeyCount: 0,
        rotateEveryN: 10,
        _extraKeys: '',
      } as RotationInfo & { _extraKeys: string },
    }))
    setSettingsDirty(true)
    closeRotationModal()
  }, [rotationModal, closeRotationModal])

  const downloadKeysTemplate = useCallback(() => {
    const keyFields: Record<string, string> = {}
    const tunnelFields: Record<string, string> = {}
    for (const [k, v] of Object.entries(settings)) {
      if (['ngrokAuthtoken', 'chiselServerUrl', 'chiselAuth'].includes(k)) {
        tunnelFields[k] = v
      } else {
        keyFields[k] = v
      }
    }
    const template = buildTemplate(keyFields, tunnelFields)
    const json = templateToJson(template)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'redamon-api-keys-template.json'
    a.click()
    URL.revokeObjectURL(url)
    toast.success('Template downloaded')
  }, [settings])

  const handleKeysFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (importFileRef.current) importFileRef.current.value = ''
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => {
      const raw = reader.result as string
      const result = validateAndParse(raw, file.size)
      if (isValidationError(result)) {
        toast.error(result.message)
        return
      }
      if (result.keyCount === 0 && result.rotationCount === 0 && result.tunnelingCount === 0) {
        toast.error('No keys to import — all values are empty or masked.')
        return
      }
      setPendingImport(result)
    }
    reader.onerror = () => toast.error('Failed to read file.')
    reader.readAsText(file)
  }, [])

  const confirmImport = useCallback(() => {
    if (!pendingImport) return
    setSettings(prev => ({ ...prev, ...pendingImport.keys, ...pendingImport.tunneling }))
    for (const [tool, cfg] of Object.entries(pendingImport.rotation)) {
      setRotationConfigs(prev => ({
        ...prev,
        [tool]: {
          extraKeyCount: cfg.extraKeys.length,
          rotateEveryN: cfg.rotateEveryN,
          _extraKeys: cfg.extraKeys.join('\n'),
        } as RotationInfo & { _extraKeys: string },
      }))
    }
    setSettingsDirty(true)
    setPendingImport(null)
    toast.success('Keys imported — click "Save Settings" to persist.')
  }, [pendingImport])

  return (
    <>
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
            <span>API Keys</span>
            <WikiInfoButton target="settings" title="Open Global Settings wiki page" />
          </h2>
          <div className={styles.sectionHeaderActions}>
            <button className={styles.sectionHeaderBtn} onClick={downloadKeysTemplate} title="Download a JSON template to fill in your API keys offline">
              <Download size={13} /> Download Template
            </button>
            <button className={styles.sectionHeaderBtn} onClick={() => importFileRef.current?.click()} title="Import API keys from a JSON template file">
              <Upload size={13} /> Import Keys
            </button>
            <input
              ref={importFileRef}
              type="file"
              accept=".json"
              style={{ display: 'none' }}
              onChange={handleKeysFileSelect}
            />
          </div>
        </div>
        {settingsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : (
          <div className={styles.settingsGrid}>
            <SecretField
              label="GitHub Access Token"
              hint="Required for GitHub Secret Hunt and TruffleHog scanners. Use repo scope for private repos, or a fine-grained token for specific repos only"
              signupUrl="https://github.com/settings/tokens"
              badges={['GitHub Secret Hunt', 'TruffleHog']}
              value={settings.githubAccessToken}
              visible={!!visibleFields.githubAccessToken}
              onToggle={() => toggleFieldVisibility('githubAccessToken')}
              onChange={v => updateSetting('githubAccessToken', v)}
            />
            <SecretField
              label="Tavily API Key"
              hint="Enables web_search tool for CVE research and exploit lookups"
              signupUrl="https://app.tavily.com/home"
              badges={['AI Agent']}
              value={settings.tavilyApiKey}
              visible={!!visibleFields.tavilyApiKey}
              onToggle={() => toggleFieldVisibility('tavilyApiKey')}
              onChange={v => updateSetting('tavilyApiKey', v)}
              onConfigureRotation={() => openRotationModal('tavilyApiKey')}
              rotationInfo={rotationConfigs.tavily || null}
            />
            <SecretField
              label="Shodan API Key"
              hint="Enables the shodan tool for internet-wide OSINT (search, host info, DNS, count)"
              signupUrl="https://account.shodan.io/"
              badges={['AI Agent', 'Recon Pipeline', 'Standalone + Uncover']}
              value={settings.shodanApiKey}
              visible={!!visibleFields.shodanApiKey}
              onToggle={() => toggleFieldVisibility('shodanApiKey')}
              onChange={v => updateSetting('shodanApiKey', v)}
              onConfigureRotation={() => openRotationModal('shodanApiKey')}
              rotationInfo={rotationConfigs.shodan || null}
            />
            <SecretField
              label="SerpAPI Key"
              hint="Enables google_dork tool for Google dorking OSINT (site:, inurl:, filetype:). Free: 250 searches/month"
              signupUrl="https://serpapi.com/manage-api-key"
              badges={['AI Agent']}
              value={settings.serpApiKey}
              visible={!!visibleFields.serpApiKey}
              onToggle={() => toggleFieldVisibility('serpApiKey')}
              onChange={v => updateSetting('serpApiKey', v)}
              onConfigureRotation={() => openRotationModal('serpApiKey')}
              rotationInfo={rotationConfigs.serp || null}
            />
            <SecretField
              label="WPScan API Token"
              hint="Enriches execute_wpscan results with vulnerability data from the WPScan database. Free: 25 requests/day"
              signupUrl="https://wpscan.com/register"
              badges={['AI Agent']}
              value={settings.wpscanApiToken}
              visible={!!visibleFields.wpscanApiToken}
              onToggle={() => toggleFieldVisibility('wpscanApiToken')}
              onChange={v => updateSetting('wpscanApiToken', v)}
              onConfigureRotation={() => openRotationModal('wpscanApiToken')}
              rotationInfo={rotationConfigs.wpscan || null}
            />
            <SecretField
              label="PDCP API Key"
              hint="Optional. Enriches the cve_intel tool by lifting the 10 req/min anonymous rate limit on ProjectDiscovery's CVE database (vulnx)."
              signupUrl="https://cloud.projectdiscovery.io"
              badges={['AI Agent']}
              value={settings.pdcpApiKey}
              visible={!!visibleFields.pdcpApiKey}
              onToggle={() => toggleFieldVisibility('pdcpApiKey')}
              onChange={v => updateSetting('pdcpApiKey', v)}
              onConfigureRotation={() => openRotationModal('pdcpApiKey')}
              rotationInfo={rotationConfigs.pdcp || null}
            />
            <SecretField
              label="NVD API Key"
              hint="NIST NVD API key — increases CVE lookup rate limit from 5 to 120 requests/30s"
              signupUrl="https://nvd.nist.gov/developers/request-an-api-key"
              badges={['Recon Pipeline']}
              value={settings.nvdApiKey}
              visible={!!visibleFields.nvdApiKey}
              onToggle={() => toggleFieldVisibility('nvdApiKey')}
              onChange={v => updateSetting('nvdApiKey', v)}
              onConfigureRotation={() => openRotationModal('nvdApiKey')}
              rotationInfo={rotationConfigs.nvd || null}
            />
            <SecretField
              label="Vulners API Key"
              hint="Vulners CVE database — alternative to NVD for vulnerability lookups with richer exploit data"
              signupUrl="https://vulners.com/#register"
              badges={['Recon Pipeline']}
              value={settings.vulnersApiKey}
              visible={!!visibleFields.vulnersApiKey}
              onToggle={() => toggleFieldVisibility('vulnersApiKey')}
              onChange={v => updateSetting('vulnersApiKey', v)}
              onConfigureRotation={() => openRotationModal('vulnersApiKey')}
              rotationInfo={rotationConfigs.vulners || null}
            />
            <SecretField
              label="URLScan API Key"
              hint="Optional — used by URLScan.io OSINT enrichment for higher rate limits. Works without key (public results only)"
              signupUrl="https://urlscan.io/user/signup"
              badges={['Recon Pipeline']}
              value={settings.urlscanApiKey}
              visible={!!visibleFields.urlscanApiKey}
              onToggle={() => toggleFieldVisibility('urlscanApiKey')}
              onChange={v => updateSetting('urlscanApiKey', v)}
              onConfigureRotation={() => openRotationModal('urlscanApiKey')}
              rotationInfo={rotationConfigs.urlscan || null}
            />
            <SecretField
              label="Censys API Token"
              hint="Censys Platform personal access token — used by Recon Pipeline and Uncover engine"
              signupUrl="https://accounts.censys.io/settings/personal-access-tokens"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.censysApiToken}
              visible={!!visibleFields.censysApiToken}
              onToggle={() => toggleFieldVisibility('censysApiToken')}
              onChange={v => updateSetting('censysApiToken', v)}
            />
            <SecretField
              label="Censys Organization ID"
              hint="Censys Organization ID — paired with API Token above. Found on your Censys account page"
              signupUrl="https://accounts.censys.io/settings/personal-access-tokens"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.censysOrgId}
              visible={!!visibleFields.censysOrgId}
              onToggle={() => toggleFieldVisibility('censysOrgId')}
              onChange={v => updateSetting('censysOrgId', v)}
            />
            <SecretField
              label="FOFA API Key"
              hint="FOFA cyberspace search engine — asset discovery with service banners, certificate info, and geolocation"
              signupUrl="https://fofa.info/personalData"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.fofaApiKey}
              visible={!!visibleFields.fofaApiKey}
              onToggle={() => toggleFieldVisibility('fofaApiKey')}
              onChange={v => updateSetting('fofaApiKey', v)}
              onConfigureRotation={() => openRotationModal('fofaApiKey')}
              rotationInfo={rotationConfigs.fofa || null}
            />
            <SecretField
              label="AlienVault OTX Key"
              hint="Open Threat Exchange — threat intelligence pulses, malware indicators, passive DNS, reputation scoring"
              signupUrl="https://otx.alienvault.com/settings"
              badges={['Recon Pipeline']}
              value={settings.otxApiKey}
              visible={!!visibleFields.otxApiKey}
              onToggle={() => toggleFieldVisibility('otxApiKey')}
              onChange={v => updateSetting('otxApiKey', v)}
              onConfigureRotation={() => openRotationModal('otxApiKey')}
              rotationInfo={rotationConfigs.otx || null}
            />
            <SecretField
              label="Netlas API Key"
              hint="Netlas.io — internet-wide scan data with banners, certificates, and WHOIS info"
              signupUrl="https://app.netlas.io/profile/"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.netlasApiKey}
              visible={!!visibleFields.netlasApiKey}
              onToggle={() => toggleFieldVisibility('netlasApiKey')}
              onChange={v => updateSetting('netlasApiKey', v)}
              onConfigureRotation={() => openRotationModal('netlasApiKey')}
              rotationInfo={rotationConfigs.netlas || null}
            />
            <SecretField
              label="VirusTotal API Key"
              hint="Multi-engine reputation for IPs and domains. Free tier: 4 lookups/min, 500/day"
              signupUrl="https://www.virustotal.com/gui/my-apikey"
              badges={['Recon Pipeline']}
              value={settings.virusTotalApiKey}
              visible={!!visibleFields.virusTotalApiKey}
              onToggle={() => toggleFieldVisibility('virusTotalApiKey')}
              onChange={v => updateSetting('virusTotalApiKey', v)}
              onConfigureRotation={() => openRotationModal('virusTotalApiKey')}
              rotationInfo={rotationConfigs.virustotal || null}
            />
            <SecretField
              label="ZoomEye API Key"
              hint="ZoomEye cyberspace search — host/device discovery with port, banner, and geo data"
              signupUrl="https://www.zoomeye.ai/profile"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.zoomEyeApiKey}
              visible={!!visibleFields.zoomEyeApiKey}
              onToggle={() => toggleFieldVisibility('zoomEyeApiKey')}
              onChange={v => updateSetting('zoomEyeApiKey', v)}
              onConfigureRotation={() => openRotationModal('zoomEyeApiKey')}
              rotationInfo={rotationConfigs.zoomeye || null}
            />
            <SecretField
              label="Criminal IP API Key"
              hint="AI-powered threat intelligence — IP/domain risk scoring, vulnerability detection, proxy/VPN/Tor identification"
              signupUrl="https://search.criminalip.io/mypage/information"
              badges={['Recon Pipeline', 'Standalone + Uncover']}
              value={settings.criminalIpApiKey}
              visible={!!visibleFields.criminalIpApiKey}
              onToggle={() => toggleFieldVisibility('criminalIpApiKey')}
              onChange={v => updateSetting('criminalIpApiKey', v)}
              onConfigureRotation={() => openRotationModal('criminalIpApiKey')}
              rotationInfo={rotationConfigs.criminalip || null}
            />

            {/* Uncover group */}
            <div style={{ borderTop: '1px solid var(--border-secondary)', marginTop: '0.75rem', paddingTop: '0.75rem' }}>
              <p style={{ fontSize: '0.75rem', color: 'var(--text-tertiary)', marginBottom: '0.5rem', textTransform: 'uppercase', letterSpacing: '0.05em', fontWeight: 600 }}>
                Uncover (Multi-Engine Search)
              </p>
            </div>
            <SecretField
              label="Quake API Key"
              hint="360 Quake cyberspace search — asset discovery by service, certificate, and banner"
              signupUrl="https://quake.360.net/quake/#/index"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.quakeApiKey}
              visible={!!visibleFields.quakeApiKey}
              onToggle={() => toggleFieldVisibility('quakeApiKey')}
              onChange={v => updateSetting('quakeApiKey', v)}
              onConfigureRotation={() => openRotationModal('quakeApiKey')}
              rotationInfo={rotationConfigs.quake || null}
            />
            <SecretField
              label="Hunter API Key"
              hint="Qianxin Hunter cyberspace search — Chinese threat intelligence platform"
              signupUrl="https://hunter.qianxin.com/"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.hunterApiKey}
              visible={!!visibleFields.hunterApiKey}
              onToggle={() => toggleFieldVisibility('hunterApiKey')}
              onChange={v => updateSetting('hunterApiKey', v)}
              onConfigureRotation={() => openRotationModal('hunterApiKey')}
              rotationInfo={rotationConfigs.hunter || null}
            />
            <SecretField
              label="PublicWWW API Key"
              hint="Search engine for source code — find websites using specific technologies, scripts, or snippets"
              signupUrl="https://publicwww.com/profile/signup.html"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.publicWwwApiKey}
              visible={!!visibleFields.publicWwwApiKey}
              onToggle={() => toggleFieldVisibility('publicWwwApiKey')}
              onChange={v => updateSetting('publicWwwApiKey', v)}
              onConfigureRotation={() => openRotationModal('publicWwwApiKey')}
              rotationInfo={rotationConfigs.publicwww || null}
            />
            <SecretField
              label="HunterHow API Key"
              hint="hunter.how internet search — asset discovery and reconnaissance"
              signupUrl="https://hunter.how/"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.hunterHowApiKey}
              visible={!!visibleFields.hunterHowApiKey}
              onToggle={() => toggleFieldVisibility('hunterHowApiKey')}
              onChange={v => updateSetting('hunterHowApiKey', v)}
              onConfigureRotation={() => openRotationModal('hunterHowApiKey')}
              rotationInfo={rotationConfigs.hunterhow || null}
            />
            <SecretField
              label="Google Custom Search API Key"
              hint="Google Custom Search JSON API — for Uncover Google search engine (different from SerpAPI)"
              signupUrl="https://developers.google.com/custom-search/v1/introduction"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.googleApiKey}
              visible={!!visibleFields.googleApiKey}
              onToggle={() => toggleFieldVisibility('googleApiKey')}
              onChange={v => updateSetting('googleApiKey', v)}
            />
            <SecretField
              label="Google Custom Search CX"
              hint="Programmable Search Engine ID — paired with Google API Key above"
              signupUrl="https://programmablesearchengine.google.com/controlpanel/create"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.googleApiCx}
              visible={!!visibleFields.googleApiCx}
              onToggle={() => toggleFieldVisibility('googleApiCx')}
              onChange={v => updateSetting('googleApiCx', v)}
            />
            <SecretField
              label="Onyphe API Key"
              hint="Onyphe — cyber defense search engine for exposed assets, threat detection, and attack surface management"
              signupUrl="https://search.onyphe.io/signup"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.onypheApiKey}
              visible={!!visibleFields.onypheApiKey}
              onToggle={() => toggleFieldVisibility('onypheApiKey')}
              onChange={v => updateSetting('onypheApiKey', v)}
              onConfigureRotation={() => openRotationModal('onypheApiKey')}
              rotationInfo={rotationConfigs.onyphe || null}
            />
            <SecretField
              label="Driftnet API Key"
              hint="Driftnet — fast internet-wide port and service discovery"
              signupUrl="https://driftnet.io/auth?state=signup"
              badges={['Uncover', 'Recon Pipeline']}
              value={settings.driftnetApiKey}
              visible={!!visibleFields.driftnetApiKey}
              onToggle={() => toggleFieldVisibility('driftnetApiKey')}
              onChange={v => updateSetting('driftnetApiKey', v)}
              onConfigureRotation={() => openRotationModal('driftnetApiKey')}
              rotationInfo={rotationConfigs.driftnet || null}
            />
          </div>
        )}
      </div>

      {/* Tunneling sub-section */}
      <div className={styles.section}>
        <div className={styles.sectionHeader}>
          <h2 className={styles.sectionTitle} style={{ display: 'inline-flex', alignItems: 'center', gap: '8px' }}>
            <span>Tunneling</span>
            <WikiInfoButton target="https://github.com/samugit83/redamon/wiki/Reverse-Shells" title="Open Reverse Shells wiki page" />
          </h2>
        </div>
        <p className={styles.sectionHint}>
          Configure reverse shell tunneling. Choose ngrok (free, single port) or chisel (multi-port, requires VPS). Changes apply immediately.
        </p>
        {settingsLoading ? (
          <div className={styles.emptyState}><Loader2 size={16} className={styles.spin} /> Loading...</div>
        ) : (
          <div className={styles.settingsGrid}>
            <SecretField
              label="ngrok Auth Token"
              hint="Enables ngrok TCP tunnel for reverse shells on port 4444. Stageless payloads only."
              signupUrl="https://dashboard.ngrok.com/get-started/your-authtoken"
              value={settings.ngrokAuthtoken}
              visible={!!visibleFields.ngrokAuthtoken}
              onToggle={() => toggleFieldVisibility('ngrokAuthtoken')}
              onChange={v => updateSetting('ngrokAuthtoken', v)}
            />
            <div className="formGroup">
              <label className="formLabel">Chisel Server URL</label>
              <input
                className="textInput"
                type="text"
                value={settings.chiselServerUrl}
                onChange={e => updateSetting('chiselServerUrl', e.target.value)}
                placeholder="e.g. http://your-vps.com:9090"
              />
              <span className="formHint">
                Your VPS chisel server URL. Run on VPS: <code>chisel server -p 9090 --reverse</code>. Tunnels ports 4444 (handler) + 8080 (web delivery).
              </span>
            </div>
            <SecretField
              label="Chisel Auth"
              hint="user:pass for chisel server authentication (optional — only if your chisel server requires auth)"
              value={settings.chiselAuth}
              visible={!!visibleFields.chiselAuth}
              onToggle={() => toggleFieldVisibility('chiselAuth')}
              onChange={v => updateSetting('chiselAuth', v)}
            />
          </div>
        )}
        {settingsDirty && !settingsSaving && (
          <div className={styles.formActions} style={{ justifyContent: 'flex-end', marginTop: '12px' }}>
            <button className="primaryButton" onClick={saveSettings} disabled={settingsSaving}>
              Save Settings
            </button>
          </div>
        )}
      </div>

      {/* Key Rotation Modal */}
      <Modal
        isOpen={!!rotationModal}
        onClose={closeRotationModal}
        title={`Key Rotation — ${rotationModal || ''}`}
        size="small"
        footer={
          <>
            {rotationConfigs[rotationModal || '']?.extraKeyCount > 0 && !rotationDraftDirty && (
              <button className="secondaryButton" onClick={clearRotationConfig} style={{ marginRight: 'auto' }}>
                Clear All Extra Keys
              </button>
            )}
            <button className="secondaryButton" onClick={closeRotationModal}>Cancel</button>
            <button
              className="primaryButton"
              onClick={saveRotationDraft}
              disabled={!rotationDraftDirty && rotationDraft.rotateEveryN === (rotationConfigs[rotationModal || '']?.rotateEveryN ?? 10)}
            >
              Save
            </button>
          </>
        }
      >
        <div className="formGroup">
          <label className="formLabel">Extra API Keys</label>
          {rotationConfigs[rotationModal || '']?.extraKeyCount > 0 && !rotationDraftDirty ? (
            <>
              <div style={{
                padding: '10px 12px',
                background: 'var(--accent-secondary-subtle)',
                borderRadius: '6px',
                fontSize: '12px',
                color: 'var(--accent-secondary)',
                marginBottom: '8px',
              }}>
                {rotationConfigs[rotationModal || '']?.extraKeyCount} extra key(s) configured. Paste new keys below to replace them.
              </div>
              <textarea
                className="textInput"
                rows={5}
                value={rotationDraft.extraKeys}
                onChange={e => {
                  setRotationDraft(prev => ({ ...prev, extraKeys: e.target.value }))
                  setRotationDraftDirty(true)
                }}
                placeholder="Paste API keys here, one per line..."
                style={{ fontFamily: 'monospace', fontSize: '12px' }}
              />
            </>
          ) : (
            <textarea
              className="textInput"
              rows={5}
              value={rotationDraft.extraKeys}
              onChange={e => {
                setRotationDraft(prev => ({ ...prev, extraKeys: e.target.value }))
                setRotationDraftDirty(true)
              }}
              placeholder="Paste API keys here, one per line..."
              style={{ fontFamily: 'monospace', fontSize: '12px' }}
              autoFocus
            />
          )}
          <span className="formHint">
            These keys plus the main key above form the rotation pool. All keys are treated equally.
          </span>
        </div>
        <div className="formGroup" style={{ marginTop: '12px' }}>
          <label className="formLabel">Rotate Every N Calls</label>
          <input
            className="textInput"
            type="number"
            min={1}
            value={rotationDraft.rotateEveryN}
            onChange={e => setRotationDraft(prev => ({ ...prev, rotateEveryN: parseInt(e.target.value, 10) || 10 }))}
            style={{ width: '120px' }}
          />
          <span className="formHint">
            After this many API calls, switch to the next key in the pool (default: 10).
          </span>
        </div>
      </Modal>

      {/* Import Keys Confirmation Modal */}
      <Modal
        isOpen={!!pendingImport}
        onClose={() => setPendingImport(null)}
        title="Import API Keys"
        size="small"
        footer={
          <>
            <button className="secondaryButton" onClick={() => setPendingImport(null)}>Cancel</button>
            <button className="primaryButton" onClick={confirmImport}>
              <Upload size={14} /> Import
            </button>
          </>
        }
      >
        {pendingImport && (
          <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
            <p style={{ marginBottom: '12px' }}>The following will be loaded into the form:</p>
            <ul style={{ margin: 0, paddingLeft: '18px' }}>
              {pendingImport.keyCount > 0 && <li><strong>{pendingImport.keyCount}</strong> API key{pendingImport.keyCount > 1 ? 's' : ''}</li>}
              {pendingImport.rotationCount > 0 && <li><strong>{pendingImport.rotationCount}</strong> rotation config{pendingImport.rotationCount > 1 ? 's' : ''}</li>}
              {pendingImport.tunnelingCount > 0 && <li><strong>{pendingImport.tunnelingCount}</strong> tunneling field{pendingImport.tunnelingCount > 1 ? 's' : ''}</li>}
            </ul>
            <p style={{ marginTop: '12px', fontSize: '12px', color: 'var(--text-tertiary)' }}>
              Empty values and masked values are skipped. You must click <strong>Save Settings</strong> after import to persist.
            </p>
          </div>
        )}
      </Modal>
    </>
  )
}

'use client'

import { useState, useMemo } from 'react'
import { ChevronDown, Target, ShieldAlert, AlertTriangle, Sparkles } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import { isHardBlockedDomain } from '@/lib/hard-guardrail'
import { FileImportButton } from '../FileImportButton'
import { ModelPicker } from '@/components/shared/ModelPicker'
import { useProject } from '@/providers/ProjectProvider'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface TargetSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  mode?: 'create' | 'edit'
}

// Helper to convert stored format (with dots) to display format (without dots)
function toDisplayPrefixes(subdomainList: string[]): string {
  return subdomainList
    .filter(s => s !== '.')  // Exclude root domain marker
    .map(s => s.endsWith('.') ? s.slice(0, -1) : s)  // Remove trailing dot
    .join(', ')
}

// Helper to convert display format to stored format (with trailing dots)
function toStoredPrefixes(displayValue: string, includeRoot: boolean): string[] {
  const prefixes = displayValue
    .split(',')
    .map(s => s.trim())
    .filter(Boolean)
    .map(s => s.endsWith('.') ? s : s + '.')  // Add trailing dot if missing

  if (includeRoot) {
    prefixes.push('.')
  }

  return prefixes
}

// Helper to parse IP textarea into array
function parseIpList(text: string): string[] {
  return text
    .split(/[,\n]/)
    .map(s => s.trim())
    .filter(Boolean)
}

export function TargetSection({ data, updateField, mode = 'create' }: TargetSectionProps) {
  const isLocked = mode === 'edit'
  const [isOpen, setIsOpen] = useState(true)
  const { userId } = useProject()

  const ipMode = data.ipMode || false

  // Check if root domain is included in the list
  const includesRootDomain = useMemo(() => data.subdomainList.includes('.'), [data.subdomainList])

  // Display value without dots
  const displayPrefixes = useMemo(() => toDisplayPrefixes(data.subdomainList), [data.subdomainList])

  // Display value for IP textarea
  const displayIps = useMemo(() => (data.targetIps || []).join('\n'), [data.targetIps])

  // Hard guardrail: deterministic check for government/public domains (non-disableable)
  const hardBlockResult = useMemo(
    () => (!ipMode && data.targetDomain ? isHardBlockedDomain(data.targetDomain) : { blocked: false, reason: '' }),
    [ipMode, data.targetDomain]
  )

  const handlePrefixesChange = (value: string) => {
    updateField('subdomainList', toStoredPrefixes(value, includesRootDomain))
  }

  const handleRootDomainToggle = (checked: boolean) => {
    const currentPrefixes = toDisplayPrefixes(data.subdomainList)
    updateField('subdomainList', toStoredPrefixes(currentPrefixes, checked))
  }

  const handleIpModeToggle = (checked: boolean) => {
    updateField('ipMode', checked)
    if (checked) {
      updateField('targetDomain', '')
      updateField('subdomainList', [])
    } else {
      updateField('targetIps', [])
    }
  }

  const handleIpsChange = (text: string) => {
    updateField('targetIps', parseIpList(text))
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Target size={16} />
          Target Configuration
          <WikiInfoButton target="Target" />
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Define the primary target for your security assessment. Choose between domain-based
            or IP-based targeting mode.
          </p>

          {/* IP Mode Toggle - locked in edit mode */}
          <div className={styles.toggleRow}>
            <div>
              <span className={styles.toggleLabel}>Start from IP</span>
              <p className={styles.toggleDescription}>
                Target IP addresses or CIDR ranges instead of a domain. The pipeline will
                attempt reverse DNS to discover hostnames.
              </p>
            </div>
            <Toggle
              checked={ipMode}
              onChange={handleIpModeToggle}
              disabled={isLocked}
            />
          </div>

          <div className={styles.fieldRow}>
            <div className={styles.fieldGroup}>
              <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                Project Name
              </label>
              <input
                type="text"
                className="textInput"
                value={data.name}
                onChange={(e) => updateField('name', e.target.value)}
                placeholder="My Security Project"
              />
            </div>

            {!ipMode && (
              <div className={styles.fieldGroup}>
                <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                  Target Domain
                </label>
                <input
                  type="text"
                  className="textInput"
                  value={data.targetDomain}
                  onChange={(e) => updateField('targetDomain', e.target.value)}
                  placeholder="example.com"
                  disabled={isLocked}
                  title={isLocked ? 'Target domain cannot be changed after creation. Create a new project instead.' : undefined}
                />
              </div>
            )}
          </div>

          {/* Hard guardrail warning for government/public domains */}
          {hardBlockResult.blocked && (
            <div className={styles.shodanWarning} style={{ borderColor: 'rgba(239, 68, 68, 0.4)', background: 'rgba(239, 68, 68, 0.08)' }}>
              <ShieldAlert size={14} style={{ color: '#ef4444' }} />
              <span>
                <strong>Target permanently blocked:</strong> Government, military, educational, and international
                organization websites (.gov, .mil, .edu, .int, etc.) are always blocked and cannot be used as targets,
                regardless of guardrail settings. This restriction cannot be disabled.
              </span>
            </div>
          )}

          {/* IP Mode: Target IPs textarea */}
          {ipMode && (
            <div className={styles.fieldGroup}>
              <label className={`${styles.fieldLabel} ${styles.fieldLabelRequired}`}>
                Target IPs / CIDRs
              </label>
              <div className={styles.fileImportWrap}>
                <textarea
                  className="textarea"
                  value={displayIps}
                  onChange={(e) => handleIpsChange(e.target.value)}
                  placeholder={"192.168.1.1\n10.0.0.0/24\n2001:db8::1"}
                  rows={4}
                  disabled={isLocked}
                  title={isLocked ? 'Target IPs cannot be changed after creation.' : undefined}
                />
                {!isLocked && (
                  <FileImportButton
                    variant="textarea"
                    fieldName="target IPs / CIDRs"
                    onImport={(values) => updateField('targetIps', values)}
                  />
                )}
              </div>
              <span className={styles.fieldHint}>
                {isLocked
                  ? 'Target IPs are locked after project creation. Create a new project to change them.'
                  : 'Enter one IP or CIDR per line, or comma-separated. IPv4, IPv6, and CIDR ranges supported. Max /24 (256 hosts).'}
              </span>
            </div>
          )}

          <div className={styles.fieldGroup}>
            <label className={styles.fieldLabel}>Description</label>
            <textarea
              className="textarea"
              value={data.description || ''}
              onChange={(e) => updateField('description', e.target.value)}
              placeholder="Project description (optional)"
              rows={2}
            />
          </div>

          {/* Domain-mode only fields */}
          {!ipMode && (
            <>
              <div className={styles.fieldGroup}>
                <label className={styles.fieldLabel}>Subdomain Prefixes</label>
                <div className={styles.fileImportWrap}>
                  <input
                    type="text"
                    className="textInput"
                    value={displayPrefixes}
                    onChange={(e) => handlePrefixesChange(e.target.value)}
                    placeholder="www, api, admin (comma-separated)"
                    disabled={isLocked}
                    title={isLocked ? 'Subdomain list cannot be changed after creation. Create a new project instead.' : undefined}
                  />
                  {!isLocked && (
                    <FileImportButton
                      fieldName="subdomain prefixes"
                      onImport={(values) => handlePrefixesChange(values.join(', '))}
                    />
                  )}
                </div>
                <span className={styles.fieldHint}>
                  {isLocked
                    ? 'Target domain and subdomains are locked after project creation to keep graph data consistent. To change them, create a new project.'
                    : 'Leave empty to discover all subdomains. Enter prefixes without dots (e.g., "www, api, admin").'}
                </span>
                {!isLocked && displayPrefixes.trim().length === 0 && (
                  <div
                    className={styles.shodanWarning}
                    style={{
                      marginTop: 'var(--space-2)',
                      marginBottom: 0,
                      padding: 'var(--space-3) var(--space-4)',
                      fontSize: 'var(--text-sm)',
                      borderWidth: '2px',
                      borderColor: 'rgba(251, 146, 60, 0.5)',
                      background: 'rgba(251, 146, 60, 0.12)',
                      alignItems: 'center',
                    }}
                  >
                    <AlertTriangle size={22} style={{ color: '#fb923c' }} />
                    <span>
                      <strong>Heads up:</strong> Leaving Subdomain Prefixes empty starts full
                      subdomain enumeration across the entire domain. This will take
                      <strong> much, much longer </strong>
                      than scanning a specific set of prefixes.
                    </span>
                  </div>
                )}
              </div>

              <div className={styles.toggleRow}>
                <div>
                  <span className={styles.toggleLabel}>Include Root Domain</span>
                  <p className={styles.toggleDescription}>
                    Also scan the root domain (e.g., example.com without subdomain)
                  </p>
                </div>
                <Toggle
                  checked={includesRootDomain}
                  onChange={handleRootDomainToggle}
                  disabled={isLocked}
                />
              </div>

              {/* AI in Pipeline (master toggle, model picker, per-tool toggles) */}
              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>
                  <Sparkles size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />
                  AI in Pipeline
                </h3>
                <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <span className={styles.toggleLabel}>Enable AI in Pipeline</span>
                    <p className={styles.toggleDescription}>
                      Master switch that unlocks every per-tool AI toggle below.
                      When OFF, all per-tool AI flags are forced OFF and disabled,
                      no LLM calls are made by the recon pipeline. When ON, each
                      per-tool toggle becomes editable and individual AI hooks can
                      be turned on or off independently. Pick the model used by
                      every hook just below.
                    </p>
                  </div>
                  <Toggle
                    checked={data.aiInPipeline}
                    onChange={(checked) => {
                      updateField('aiInPipeline', checked)
                      // When master flips, cascade to every per-tool flag so the
                      // form state matches the backend defense-in-depth contract.
                      updateField('ffufAiExtensions', checked)
                    }}
                  />
                </div>
                {data.aiInPipeline && (
                  <>
                    <div className={styles.fieldRow} style={{ marginTop: 'var(--space-3)' }}>
                      <div className={styles.fieldGroup}>
                        <label className={styles.fieldLabel}>AI Model</label>
                        <ModelPicker
                          userId={userId}
                          value={data.aiPipelineModel}
                          onChange={(id) => updateField('aiPipelineModel', id)}
                        />
                        <span className={styles.fieldHint}>
                          Model used by every AI hook in recon. Independent of the
                          agent&apos;s own model selection. Pick a cheaper model here
                          if cost matters more than peak quality.
                        </span>
                      </div>
                    </div>

                    {/* Per-tool AI toggles. Each one mirrors the toggle in its tool
                        section, sharing the same form field, so flipping either
                        place updates both. Add new entries here as more tools gain
                        AI hooks. */}
                    <div style={{ marginTop: 'var(--space-4)' }}>
                      <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <span className={styles.toggleLabel}>FFuf: Use AI for Extensions</span>
                          <p className={styles.toggleDescription}>
                            For each fuzz target, FFuf first sends a single HEAD
                            request and asks the configured model to suggest the
                            most likely file extensions based on the response
                            headers (Server, X-Powered-By, X-AspNet-Version).
                            The static FFuf extensions list in the FFuf module is
                            ignored when this is on. Same toggle as in the FFuf
                            module: flipping it here flips it there. A
                            per-fingerprint cache means N hosts behind the same
                            stack collapse to one LLM call.
                          </p>
                        </div>
                        <Toggle
                          checked={data.ffufAiExtensions}
                          onChange={(checked) => updateField('ffufAiExtensions', checked)}
                        />
                      </div>
                    </div>
                  </>
                )}
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Domain Verification</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Verify Domain Ownership</span>
                    <p className={styles.toggleDescription}>
                      Require DNS TXT record verification before scanning
                    </p>
                  </div>
                  <Toggle
                    checked={data.verifyDomainOwnership}
                    onChange={(checked) => updateField('verifyDomainOwnership', checked)}
                  />
                </div>

                {data.verifyDomainOwnership && (
                  <div className={styles.fieldRow}>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>Ownership Token</label>
                      <input
                        type="text"
                        className="textInput"
                        value={data.ownershipToken}
                        onChange={(e) => updateField('ownershipToken', e.target.value)}
                      />
                    </div>
                    <div className={styles.fieldGroup}>
                      <label className={styles.fieldLabel}>TXT Record Prefix</label>
                      <input
                        type="text"
                        className="textInput"
                        value={data.ownershipTxtPrefix}
                        onChange={(e) => updateField('ownershipTxtPrefix', e.target.value)}
                      />
                    </div>
                  </div>
                )}
              </div>
            </>
          )}

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Stealth Mode</h3>
            <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span className={styles.toggleLabel}>Enable Stealth Mode</span>
                <p className={styles.toggleDescription}>
                  Force the entire pipeline to use only passive and low-noise techniques.
                  Active scanners (Kiterunner, banner grabbing) are disabled. Port scanning
                  switches to passive mode. Nuclei disables DAST and interactsh. The AI agent
                  uses only stealthy methods and will stop if stealth is impossible for a
                  requested action.
                </p>
              </div>
              <Toggle
                checked={data.stealthMode}
                onChange={(checked) => updateField('stealthMode', checked)}
              />
            </div>
          </div>

          {/* Target Guardrail */}
          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Target Guardrail</h3>
            <div className={styles.toggleRow} style={{ gap: 'var(--space-4)' }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <span className={styles.toggleLabel}>Enable Target Guardrail</span>
                <p className={styles.toggleDescription}>
                  Block well-known public targets (major tech companies,
                  cloud providers, financial institutions, etc.) when saving the project.
                  Prevents accidental scanning of unauthorized domains.
                  Government, military, educational, and international organization domains
                  (.gov, .mil, .edu, .int) are always blocked regardless of this setting.
                </p>
              </div>
              <Toggle
                checked={data.targetGuardrailEnabled ?? true}
                onChange={(checked) => updateField('targetGuardrailEnabled', checked)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

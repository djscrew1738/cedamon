'use client'

import { useState } from 'react'
import { ChevronDown, FolderSearch, Play } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'
import { NodeInfoTooltip } from '../NodeInfoTooltip'
import { FileImportButton } from '../FileImportButton'
import { AiToggleLabel } from '../AiToggleLabel'
import { WordlistManager } from '../WordlistManager'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

const WEB_CONTENT_BUILTINS = [
  { name: 'common.txt', path: '/usr/share/seclists/Discovery/Web-Content/common.txt', size: '25KB', desc: 'Most common paths' },
  { name: 'directory-list-2.3-small.txt', path: '/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt', size: '400KB', desc: 'Small directory list' },
  { name: 'raft-medium-directories.txt', path: '/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt', size: '890KB', desc: 'Raft medium' },
]

interface CustomWordlist {
  name: string
  path: string
  size: number
}

interface FfufSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
  projectId?: string
  mode: 'create' | 'edit'
  onRun?: () => void
}

export function FfufSection({ data, updateField, projectId, mode, onRun }: FfufSectionProps) {
  const [isOpen, setIsOpen] = useState(true)
  const [customWordlists, setCustomWordlists] = useState<CustomWordlist[]>([])

  const formatSize = (bytes: number) => {
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <FolderSearch size={16} />
          FFuf Directory Fuzzer
          <NodeInfoTooltip section="Ffuf" />
          <WikiInfoButton target="Ffuf" />
          <span className={styles.badgeActive}>Active</span>
        </h2>
        <div className={styles.sectionHeaderRight}>
          {onRun && data.ffufEnabled && (
            <button
              type="button"
              onClick={(e) => { e.stopPropagation(); onRun() }}
              style={{
                display: 'inline-flex', alignItems: 'center', gap: '4px',
                padding: '3px 8px', borderRadius: '4px',
                border: '1px solid rgba(34, 197, 94, 0.3)',
                backgroundColor: 'rgba(34, 197, 94, 0.1)',
                color: '#22c55e', cursor: 'pointer', fontSize: '11px', fontWeight: 500,
              }}
              title="Run FFuf"
            >
              <Play size={10} /> Run partial recon
            </button>
          )}
          <div onClick={(e) => e.stopPropagation()}>
            <Toggle
              checked={data.ffufEnabled}
              onChange={(checked) => updateField('ffufEnabled', checked)}
            />
          </div>
          <ChevronDown
            size={16}
            className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
          />
        </div>
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Fast directory and endpoint fuzzer that brute-forces common paths using wordlists. Discovers hidden content (admin panels, backup files, configs, undocumented APIs) that crawlers cannot find. Runs after crawlers complete and can target discovered base paths for smart fuzzing.
          </p>

          {data.ffufEnabled && (
            <>
              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Threads</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufThreads}
                    onChange={(e) => updateField('ffufThreads', parseInt(e.target.value) || 40)}
                    min={1}
                    max={200}
                  />
                  <span className={styles.fieldHint}>Concurrent request threads</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Rate Limit (req/s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufRate}
                    onChange={(e) => updateField('ffufRate', parseInt(e.target.value) || 0)}
                    min={0}
                  />
                  <span className={styles.fieldHint}>Max requests per second (0 = unlimited)</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Parallelism</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufParallelism ?? 20}
                    onChange={(e) => updateField('ffufParallelism', parseInt(e.target.value) || 20)}
                    min={1}
                    max={50}
                  />
                  <span className={styles.fieldHint}>Number of targets to fuzz in parallel</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Timeout (s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufTimeout}
                    onChange={(e) => updateField('ffufTimeout', parseInt(e.target.value) || 10)}
                    min={1}
                  />
                  <span className={styles.fieldHint}>Per-request timeout</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Max Time (s)</label>
                  <input
                    type="number"
                    className="textInput"
                    value={data.ffufMaxTime}
                    onChange={(e) => updateField('ffufMaxTime', parseInt(e.target.value) || 1800)}
                    min={60}
                  />
                  <span className={styles.fieldHint}>Maximum total execution time per target</span>
                </div>
              </div>

              <div className={styles.fieldGroup}>
                <WordlistManager
                  value={(data.ffufWordlist as string) || ''}
                  onChange={(path) => updateField('ffufWordlist', path)}
                  projectId={projectId}
                  label="Wordlist"
                  categories={['Web Content', 'API Endpoints', 'Fuzzing']}
                  extraBuiltins={WEB_CONTENT_BUILTINS}
                  allowUpload={!!projectId}
                />
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Match Status Codes</label>
                  <div className={styles.fileImportWrap}>
                    <input
                      type="text"
                      className="textInput"
                      value={(data.ffufMatchCodes ?? []).join(', ')}
                      onChange={(e) => updateField('ffufMatchCodes', e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)))}
                    />
                    <FileImportButton
                      fieldName="status codes"
                      validator={(t) => /^\d+$/.test(t)}
                      onImport={(values) => updateField('ffufMatchCodes', values.map(v => parseInt(v)).filter(n => !isNaN(n)))}
                    />
                  </div>
                  <span className={styles.fieldHint}>Include these HTTP status codes (comma-separated)</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Filter Status Codes</label>
                  <div className={styles.fileImportWrap}>
                    <input
                      type="text"
                      className="textInput"
                      value={(data.ffufFilterCodes ?? []).join(', ')}
                      onChange={(e) => updateField('ffufFilterCodes', e.target.value.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n)))}
                    />
                    <FileImportButton
                      fieldName="status codes"
                      validator={(t) => /^\d+$/.test(t)}
                      onImport={(values) => updateField('ffufFilterCodes', values.map(v => parseInt(v)).filter(n => !isNaN(n)))}
                    />
                  </div>
                  <span className={styles.fieldHint}>Exclude these HTTP status codes (comma-separated)</span>
                </div>
              </div>

              <div className={styles.fieldRow}>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Filter Response Size</label>
                  <input
                    type="text"
                    className="textInput"
                    value={data.ffufFilterSize}
                    onChange={(e) => updateField('ffufFilterSize', e.target.value)}
                    placeholder="e.g., 0 or 4242"
                  />
                  <span className={styles.fieldHint}>Exclude responses of this size (bytes). Useful for uniform error pages</span>
                </div>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Extensions</label>
                  <div className={styles.toggleRow} style={{ marginBottom: 'var(--space-2)', alignItems: 'center' }}>
                    <AiToggleLabel
                      label="Use AI for Extensions"
                      tooltip={
                        'AI picks file extensions per target based on server response headers ' +
                        '(Server, X-Powered-By, X-AspNet-Version). When on, the static list below ' +
                        'is ignored. Same toggle as in the Target tab AI panel: flipping it here ' +
                        'flips it there. A per-fingerprint cache means N hosts behind the same ' +
                        'stack collapse to one LLM call. ' +
                        (!data.aiInPipeline ? 'Enable "AI in Pipeline" in the Target tab to use this.' : '')
                      }
                    />
                    <Toggle
                      checked={data.ffufAiExtensions}
                      disabled={!data.aiInPipeline}
                      onChange={(checked) => updateField('ffufAiExtensions', checked)}
                    />
                  </div>
                  <div className={styles.fileImportWrap}>
                    <input
                      type="text"
                      className="textInput"
                      value={(data.ffufExtensions ?? []).join(', ')}
                      onChange={(e) => updateField('ffufExtensions', e.target.value.split(',').map(s => s.trim()).filter(Boolean))}
                      placeholder=".php, .bak, .env, .json"
                      disabled={data.ffufAiExtensions}
                      style={data.ffufAiExtensions ? { opacity: 0.5 } : undefined}
                    />
                    <FileImportButton
                      fieldName="extensions"
                      onImport={(values) => updateField('ffufExtensions', values)}
                    />
                  </div>
                  <span className={styles.fieldHint}>
                    {data.ffufAiExtensions
                      ? 'Extensions chosen by AI per target. Static list above is ignored.'
                      : 'File extensions to append to each word (comma-separated)'}
                  </span>
                </div>
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Options</h3>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Auto-Calibrate</span>
                    <p className={styles.toggleDescription}>Automatically filter false positives based on response patterns</p>
                  </div>
                  <Toggle
                    checked={data.ffufAutoCalibrate}
                    onChange={(checked) => updateField('ffufAutoCalibrate', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Smart Fuzz (Post-Crawler)</span>
                    <p className={styles.toggleDescription}>Also fuzz under base paths discovered by crawlers (e.g., /api/v1/FUZZ)</p>
                  </div>
                  <Toggle
                    checked={data.ffufSmartFuzz}
                    onChange={(checked) => updateField('ffufSmartFuzz', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Follow Redirects</span>
                    <p className={styles.toggleDescription}>Follow HTTP redirects. May lead to out-of-scope domains (filtered post-hoc)</p>
                  </div>
                  <Toggle
                    checked={data.ffufFollowRedirects}
                    onChange={(checked) => updateField('ffufFollowRedirects', checked)}
                  />
                </div>
                <div className={styles.toggleRow}>
                  <div>
                    <span className={styles.toggleLabel}>Recursion</span>
                    <p className={styles.toggleDescription}>Recursively fuzz discovered directories</p>
                  </div>
                  <Toggle
                    checked={data.ffufRecursion}
                    onChange={(checked) => updateField('ffufRecursion', checked)}
                  />
                </div>
                {data.ffufRecursion && (
                  <div className={styles.fieldGroup} style={{ marginTop: '0.5rem' }}>
                    <label className={styles.fieldLabel}>Recursion Depth</label>
                    <input
                      type="number"
                      className="textInput"
                      value={data.ffufRecursionDepth}
                      onChange={(e) => updateField('ffufRecursionDepth', parseInt(e.target.value) || 2)}
                      min={1}
                      max={5}
                    />
                  </div>
                )}
              </div>

              <div className={styles.subSection}>
                <h3 className={styles.subSectionTitle}>Custom Headers</h3>
                <div className={styles.fieldGroup}>
                  <label className={styles.fieldLabel}>Request Headers</label>
                  <div className={styles.fileImportWrap}>
                    <textarea
                      className="textarea"
                      value={(data.ffufCustomHeaders ?? []).join('\n')}
                      onChange={(e) => updateField('ffufCustomHeaders', e.target.value.split('\n').filter(Boolean))}
                      placeholder="Cookie: session=abc123&#10;Authorization: Bearer token..."
                      rows={3}
                    />
                    <FileImportButton
                      variant="textarea"
                      fieldName="headers"
                      onImport={(values) => updateField('ffufCustomHeaders', values)}
                    />
                  </div>
                  <span className={styles.fieldHint}>One header per line. Sent with every request</span>
                </div>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  )
}

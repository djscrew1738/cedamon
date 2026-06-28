'use client'

import { useState } from 'react'
import { ChevronDown, Layers } from 'lucide-react'
import { Toggle, WikiInfoButton } from '@/components/ui'
import type { Project } from '@prisma/client'
import styles from '../ProjectForm.module.css'

type FormData = Omit<Project, 'id' | 'userId' | 'createdAt' | 'updatedAt' | 'user'>

interface ScanModulesSectionProps {
  data: FormData
  updateField: <K extends keyof FormData>(field: K, value: FormData[K]) => void
}

const SCAN_MODULE_OPTIONS = [
  { id: 'domain_discovery', label: 'Discovery & OSINT', description: 'Subdomain enumeration, Shodan, URLScan', indent: 0 },
  { id: 'port_scan', label: 'Port Scanning', description: 'Naabu + Masscan port scanners', indent: 1 },
  { id: 'http_probe', label: 'HTTP Probing', description: 'httpx HTTP analysis', indent: 2 },
  { id: 'resource_enum', label: 'Resource Enumeration', description: 'Katana, GAU, Kiterunner', indent: 3 },
  { id: 'vuln_scan', label: 'Vulnerability Scanning', description: 'Nuclei vulnerability scanner', indent: 3 },
]

// Scan intensity presets: which modules are enabled at each level
const SCAN_INTENSITY_PRESETS: Record<string, string[]> = {
  quick: ['domain_discovery', 'port_scan', 'http_probe'],
  standard: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
  deep: ['domain_discovery', 'port_scan', 'http_probe', 'resource_enum', 'vuln_scan'],
}

const SCAN_INTENSITY_OPTIONS = [
  { id: 'quick', label: 'Quick', description: 'Core recon: domain → ports → HTTP' },
  { id: 'standard', label: 'Standard', description: 'Full pipeline including resource enum + vuln scan' },
  { id: 'deep', label: 'Deep', description: 'All modules, Masscan + Naabu, max thoroughness' },
] as const

type ScanIntensity = typeof SCAN_INTENSITY_OPTIONS[number]['id']

function detectCurrentIntensity(modules: string[]): ScanIntensity | null {
  for (const opt of SCAN_INTENSITY_OPTIONS) {
    const preset = SCAN_INTENSITY_PRESETS[opt.id]
    if (preset.length === modules.length && preset.every(m => modules.includes(m))) {
      return opt.id
    }
  }
  return null
}

// Module dependency tree: child → parent
const MODULE_DEPENDENCIES: Record<string, string | null> = {
  domain_discovery: null,
  port_scan: 'domain_discovery',
  http_probe: 'port_scan',
  resource_enum: 'http_probe',
  vuln_scan: 'http_probe',
}

// Get all modules that depend on a given module (direct + transitive)
function getDependentModules(moduleId: string): string[] {
  const dependents: string[] = []
  for (const [id, parent] of Object.entries(MODULE_DEPENDENCIES)) {
    if (parent === moduleId) {
      dependents.push(id, ...getDependentModules(id))
    }
  }
  return dependents
}

// Check if a module's parent chain is all enabled
function isParentEnabled(moduleId: string, enabledModules: string[]): boolean {
  const parent = MODULE_DEPENDENCIES[moduleId]
  if (parent === null) return true
  if (!enabledModules.includes(parent)) return false
  return isParentEnabled(parent, enabledModules)
}

export function ScanModulesSection({ data, updateField }: ScanModulesSectionProps) {
  const [isOpen, setIsOpen] = useState(true)

  const currentIntensity = detectCurrentIntensity(data.scanModules)

  const applyIntensity = (intensity: ScanIntensity) => {
    const preset = SCAN_INTENSITY_PRESETS[intensity]
    updateField('scanModules', [...preset])
    // Deep: also enable Masscan for maximum port coverage
    if (intensity === 'deep') {
      updateField('masscanEnabled', true as FormData['masscanEnabled'])
    }
  }

  const toggleModule = (moduleId: string) => {
    const current = data.scanModules
    if (current.includes(moduleId)) {
      // Disabling: also disable all dependent modules
      const dependents = getDependentModules(moduleId)
      const toRemove = new Set([moduleId, ...dependents])
      updateField('scanModules', current.filter(m => !toRemove.has(m)))
    } else {
      // Enabling: also enable all parent modules in the chain
      const toAdd = [moduleId]
      let parent = MODULE_DEPENDENCIES[moduleId]
      while (parent !== null) {
        if (!current.includes(parent)) {
          toAdd.push(parent)
        }
        parent = MODULE_DEPENDENCIES[parent]
      }
      updateField('scanModules', [...current, ...toAdd])
    }
  }

  return (
    <div className={styles.section}>
      <div className={styles.sectionHeader} onClick={() => setIsOpen(!isOpen)}>
        <h2 className={styles.sectionTitle}>
          <Layers size={16} />
          Scan Modules
          <WikiInfoButton target="ScanModules" />
        </h2>
        <ChevronDown
          size={16}
          className={`${styles.sectionIcon} ${isOpen ? styles.sectionIconOpen : ''}`}
        />
      </div>

      {isOpen && (
        <div className={styles.sectionContent}>
          <p className={styles.sectionDescription}>
            Control the reconnaissance pipeline by enabling or disabling specific modules. Each module builds upon the results of its parent, creating a comprehensive attack surface map from domain discovery through vulnerability detection.
          </p>

          {/* Scan intensity presets */}
          <div className={styles.intensitySelector}>
            <span className={styles.intensityLabel}>Scan Intensity</span>
            <div className={styles.intensityOptions}>
              {SCAN_INTENSITY_OPTIONS.map(opt => (
                <button
                  key={opt.id}
                  type="button"
                  className={`${styles.intensityOption} ${currentIntensity === opt.id ? styles.intensityOptionActive : ''}`}
                  onClick={() => applyIntensity(opt.id)}
                  title={opt.description}
                  aria-pressed={currentIntensity === opt.id}
                >
                  <span className={styles.intensityOptionLabel}>{opt.label}</span>
                  <span className={styles.intensityOptionDesc}>{opt.description}</span>
                </button>
              ))}
            </div>
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>Enabled Modules</h3>
            <p className={`${styles.fieldHint} ${styles.fieldHintSpaced}`}>
              Modules have dependencies: disabling a parent disables all children
            </p>
            {SCAN_MODULE_OPTIONS.map(module => {
              const isEnabled = data.scanModules.includes(module.id)
              const parentEnabled = isParentEnabled(module.id, data.scanModules)
              const isDisabledByParent = !parentEnabled && !isEnabled
              const indentClass = module.indent === 1 ? styles.toggleRowIndent1
                : module.indent === 2 ? styles.toggleRowIndent2
                : module.indent === 3 ? styles.toggleRowIndent3
                : ''

              return (
                <div
                  key={module.id}
                  className={`${styles.toggleRow} ${indentClass} ${isDisabledByParent ? styles.toggleRowMuted : ''}`}
                >
                  <div>
                    <span className={styles.toggleLabel}>
                      {module.indent > 0 && '└ '}
                      {module.label}
                    </span>
                    <p className={styles.toggleDescription}>
                      {module.description}
                      {isDisabledByParent && ' (requires parent module)'}
                    </p>
                  </div>
                  <Toggle
                    checked={isEnabled}
                    onChange={() => toggleModule(module.id)}
                  />
                </div>
              )
            })}
          </div>

          <div className={styles.subSection}>
            <h3 className={styles.subSectionTitle}>General Options</h3>
            <div className={`${styles.toggleRow} ${styles.toggleRowDisabled}`}>
              <div>
                <span className={styles.toggleLabel}>Update Graph Database</span>
                <p className={styles.toggleDescription}>
                  Store scan results in Neo4j graph database (always enabled)
                </p>
              </div>
              <Toggle
                checked={true}
                onChange={() => {}}
                disabled
              />
            </div>
            <div className={styles.toggleRow}>
              <div>
                <span className={styles.toggleLabel}>Use Tor for Recon</span>
                <p className={styles.toggleDescription}>
                  Route reconnaissance traffic through Tor network
                </p>
              </div>
              <Toggle
                checked={data.useTorForRecon}
                onChange={(checked) => updateField('useTorForRecon', checked)}
              />
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

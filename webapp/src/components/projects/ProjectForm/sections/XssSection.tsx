'use client'

import { Toggle } from '@/components/ui/Toggle/Toggle'
import styles from '../ProjectForm.module.css'

interface XssSubConfig {
  reflected?: boolean
  stored?: boolean
  dom?: boolean
  blind?: boolean
  wafBypass?: boolean
  cspBypass?: boolean
}

interface AttackSkillConfig {
  builtIn: Record<string, boolean>
  user: Record<string, boolean>
  xssConfig?: XssSubConfig
}

interface XssSectionProps {
  config: AttackSkillConfig
  onConfigChange: (config: AttackSkillConfig) => void
}

const DEFAULTS: XssSubConfig = {
  reflected: true,
  stored: true,
  dom: true,
  blind: false,
  wafBypass: true,
  cspBypass: false,
}

export function XssSection({ config, onConfigChange }: XssSectionProps) {
  const xss = { ...DEFAULTS, ...(config.xssConfig || {}) }

  const toggle = (key: keyof XssSubConfig, value: boolean) => {
    onConfigChange({
      ...config,
      xssConfig: { ...xss, [key]: value },
    })
  }

  return (
    <div className={styles.subSection}>
      <h3 className={styles.subSectionTitle}>XSS Scan Settings</h3>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Reflected XSS</span>
          <p className={styles.toggleDescription}>
            Test query parameters, form fields, and HTTP headers for reflected injection
          </p>
        </div>
        <Toggle checked={xss.reflected !== false} onChange={(v) => toggle('reflected', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Stored XSS</span>
          <p className={styles.toggleDescription}>
            Inject payloads into form submissions and check for persistent cross-site scripting
          </p>
        </div>
        <Toggle checked={xss.stored !== false} onChange={(v) => toggle('stored', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>DOM-based XSS</span>
          <p className={styles.toggleDescription}>
            Analyse JavaScript sinks (eval, innerHTML, document.write) with taint tracking
          </p>
        </div>
        <Toggle checked={xss.dom !== false} onChange={(v) => toggle('dom', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Blind XSS</span>
          <p className={styles.toggleDescription}>
            Deploy callback-based payloads and monitor for out-of-band execution
          </p>
        </div>
        <Toggle checked={xss.blind === true} onChange={(v) => toggle('blind', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>WAF Bypass</span>
          <p className={styles.toggleDescription}>
            Use encoding obfuscation, polyglot payloads, and mutation techniques to evade WAF filters
          </p>
        </div>
        <Toggle checked={xss.wafBypass !== false} onChange={(v) => toggle('wafBypass', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>CSP Bypass Analysis</span>
          <p className={styles.toggleDescription}>
            Evaluate Content-Security-Policy headers for bypass vectors (JSONP, Angular, CDN whitelists)
          </p>
        </div>
        <Toggle checked={xss.cspBypass === true} onChange={(v) => toggle('cspBypass', v)} />
      </div>
    </div>
  )
}

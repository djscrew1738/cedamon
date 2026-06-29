'use client'

import { Toggle } from '@/components/ui/Toggle/Toggle'
import styles from '../ProjectForm.module.css'

interface LlmSubConfig {
  promptInjection?: boolean
  jailbreaking?: boolean
  modelExtraction?: boolean
  ragPoisoning?: boolean
  contentFilterBypass?: boolean
  excessiveAgency?: boolean
}

interface AttackSkillConfig {
  builtIn: Record<string, boolean>
  user: Record<string, boolean>
  llmConfig?: LlmSubConfig
}

interface LlmSecuritySectionProps {
  config: AttackSkillConfig
  onConfigChange: (config: AttackSkillConfig) => void
}

const DEFAULTS: LlmSubConfig = {
  promptInjection: true,
  jailbreaking: true,
  modelExtraction: false,
  ragPoisoning: true,
  contentFilterBypass: false,
  excessiveAgency: true,
}

export function LlmSecuritySection({ config, onConfigChange }: LlmSecuritySectionProps) {
  const llm = { ...DEFAULTS, ...(config.llmConfig || {}) }

  const toggle = (key: keyof LlmSubConfig, value: boolean) => {
    onConfigChange({
      ...config,
      llmConfig: { ...llm, [key]: value },
    })
  }

  return (
    <div className={styles.subSection}>
      <h3 className={styles.subSectionTitle}>LLM Security Scan Settings</h3>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Prompt Injection</span>
          <p className={styles.toggleDescription}>
            Test with direct, indirect, and multi-turn injection payloads across chat, tool, and system prompts
          </p>
        </div>
        <Toggle checked={llm.promptInjection !== false} onChange={(v) => toggle('promptInjection', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Jailbreaking</span>
          <p className={styles.toggleDescription}>
            Attempt role-play, encoding, token-smuggling, and persona-splitting bypass techniques
          </p>
        </div>
        <Toggle checked={llm.jailbreaking !== false} onChange={(v) => toggle('jailbreaking', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Model Extraction</span>
          <p className={styles.toggleDescription}>
            Probe for architecture details, training data leakage, and parameter memorization
          </p>
        </div>
        <Toggle checked={llm.modelExtraction === true} onChange={(v) => toggle('modelExtraction', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>RAG Pipeline Poisoning</span>
          <p className={styles.toggleDescription}>
            Inject malicious documents, test embedding-space attacks, and check retrieval integrity
          </p>
        </div>
        <Toggle checked={llm.ragPoisoning !== false} onChange={(v) => toggle('ragPoisoning', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Content Filter Bypass</span>
          <p className={styles.toggleDescription}>
            Test safety-guardrail evasion via encoding tricks, language switching, and context manipulation
          </p>
        </div>
        <Toggle checked={llm.contentFilterBypass === true} onChange={(v) => toggle('contentFilterBypass', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Excessive Agency Exploits</span>
          <p className={styles.toggleDescription}>
            Check for over-privileged tool access, missing confirmation gates, and plugin abuse vectors
          </p>
        </div>
        <Toggle checked={llm.excessiveAgency !== false} onChange={(v) => toggle('excessiveAgency', v)} />
      </div>
    </div>
  )
}

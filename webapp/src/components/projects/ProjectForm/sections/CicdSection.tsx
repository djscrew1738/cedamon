'use client'

import { Toggle } from '@/components/ui/Toggle/Toggle'
import styles from '../ProjectForm.module.css'

interface CicdSubConfig {
  githubActions?: boolean
  gitlabCi?: boolean
  jenkins?: boolean
  dependencyConfusion?: boolean
  artifactPoisoning?: boolean
  runnerCompromise?: boolean
}

interface AttackSkillConfig {
  builtIn: Record<string, boolean>
  user: Record<string, boolean>
  cicdConfig?: CicdSubConfig
}

interface CicdSectionProps {
  config: AttackSkillConfig
  onConfigChange: (config: AttackSkillConfig) => void
}

const DEFAULTS: CicdSubConfig = {
  githubActions: true,
  gitlabCi: true,
  jenkins: false,
  dependencyConfusion: true,
  artifactPoisoning: false,
  runnerCompromise: false,
}

export function CicdSection({ config, onConfigChange }: CicdSectionProps) {
  const cicd = { ...DEFAULTS, ...(config.cicdConfig || {}) }

  const toggle = (key: keyof CicdSubConfig, value: boolean) => {
    onConfigChange({
      ...config,
      cicdConfig: { ...cicd, [key]: value },
    })
  }

  return (
    <div className={styles.subSection}>
      <h3 className={styles.subSectionTitle}>CI/CD Pipeline Scan Settings</h3>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>GitHub Actions</span>
          <p className={styles.toggleDescription}>
            Audit workflow YAMLs, check pull_request_target usage, and review OIDC trust configurations
          </p>
        </div>
        <Toggle checked={cicd.githubActions !== false} onChange={(v) => toggle('githubActions', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>GitLab CI</span>
          <p className={styles.toggleDescription}>
            Inspect .gitlab-ci.yml for pipeline-based privilege escalation and protected branch bypasses
          </p>
        </div>
        <Toggle checked={cicd.gitlabCi !== false} onChange={(v) => toggle('gitlabCi', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Jenkins</span>
          <p className={styles.toggleDescription}>
            Enumerate jobs, check script console access, and test Groovy sandbox escapes
          </p>
        </div>
        <Toggle checked={cicd.jenkins === true} onChange={(v) => toggle('jenkins', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Dependency Confusion</span>
          <p className={styles.toggleDescription}>
            Identify private package names and test for namespace-confusion supply-chain injection
          </p>
        </div>
        <Toggle checked={cicd.dependencyConfusion !== false} onChange={(v) => toggle('dependencyConfusion', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Artifact Poisoning</span>
          <p className={styles.toggleDescription}>
            Check for unsigned build artifacts, cache poisoning, and tampered release assets
          </p>
        </div>
        <Toggle checked={cicd.artifactPoisoning === true} onChange={(v) => toggle('artifactPoisoning', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Self-Hosted Runner Compromise</span>
          <p className={styles.toggleDescription}>
            Assess ephemeral runner isolation, fork-PR safety, and persistent runner backdoor vectors
          </p>
        </div>
        <Toggle checked={cicd.runnerCompromise === true} onChange={(v) => toggle('runnerCompromise', v)} />
      </div>
    </div>
  )
}

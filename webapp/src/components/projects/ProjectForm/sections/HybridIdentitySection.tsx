'use client'

import { Toggle } from '@/components/ui/Toggle/Toggle'
import styles from '../ProjectForm.module.css'

interface IdentitySubConfig {
  adfsCompromise?: boolean
  azureAdConnect?: boolean
  kerberosDelegation?: boolean
  samlFederation?: boolean
  crossForestPivot?: boolean
  entraTokenTheft?: boolean
}

interface AttackSkillConfig {
  builtIn: Record<string, boolean>
  user: Record<string, boolean>
  identityConfig?: IdentitySubConfig
}

interface HybridIdentitySectionProps {
  config: AttackSkillConfig
  onConfigChange: (config: AttackSkillConfig) => void
}

const DEFAULTS: IdentitySubConfig = {
  adfsCompromise: true,
  azureAdConnect: true,
  kerberosDelegation: false,
  samlFederation: true,
  crossForestPivot: false,
  entraTokenTheft: true,
}

export function HybridIdentitySection({ config, onConfigChange }: HybridIdentitySectionProps) {
  const id = { ...DEFAULTS, ...(config.identityConfig || {}) }

  const toggle = (key: keyof IdentitySubConfig, value: boolean) => {
    onConfigChange({
      ...config,
      identityConfig: { ...id, [key]: value },
    })
  }

  return (
    <div className={styles.subSection}>
      <h3 className={styles.subSectionTitle}>Hybrid Identity Scan Settings</h3>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>AD FS Compromise</span>
          <p className={styles.toggleDescription}>
            Enumerate federation metadata, test token-signing certificate theft, and golden SAML attacks
          </p>
        </div>
        <Toggle checked={id.adfsCompromise !== false} onChange={(v) => toggle('adfsCompromise', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Azure AD Connect Abuse</span>
          <p className={styles.toggleDescription}>
            Extract MSOL account credentials, dump sync'd password hashes, and pivot to cloud tenant
          </p>
        </div>
        <Toggle checked={id.azureAdConnect !== false} onChange={(v) => toggle('azureAdConnect', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Kerberos Delegation Attacks</span>
          <p className={styles.toggleDescription}>
            Enumerate constrained/unconstrained delegation, resource-based constrained delegation, and ticket forgery
          </p>
        </div>
        <Toggle checked={id.kerberosDelegation === true} onChange={(v) => toggle('kerberosDelegation', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>SAML Federation Trust Attacks</span>
          <p className={styles.toggleDescription}>
            Analyse SAML trust relationships, test IdP-initiated flows, and check for XML signature wrapping
          </p>
        </div>
        <Toggle checked={id.samlFederation !== false} onChange={(v) => toggle('samlFederation', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Cross-Forest Pivots</span>
          <p className={styles.toggleDescription}>
            Enumerate forest trusts, attempt SID history injection, and pivot across domain boundaries
          </p>
        </div>
        <Toggle checked={id.crossForestPivot === true} onChange={(v) => toggle('crossForestPivot', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Entra ID Token Theft</span>
          <p className={styles.toggleDescription}>
            Test for PRT cookie extraction, refresh-token replay, and device-registration abuse
          </p>
        </div>
        <Toggle checked={id.entraTokenTheft !== false} onChange={(v) => toggle('entraTokenTheft', v)} />
      </div>
    </div>
  )
}

'use client'

import { Toggle } from '@/components/ui/Toggle/Toggle'
import styles from '../ProjectForm.module.css'

interface K8sSubConfig {
  registryScan?: boolean
  rbacEnum?: boolean
  podBreakout?: boolean
  etcdExposure?: boolean
  admissionAudit?: boolean
  networkPolicy?: boolean
}

interface AttackSkillConfig {
  builtIn: Record<string, boolean>
  user: Record<string, boolean>
  k8sConfig?: K8sSubConfig
}

interface ContainerK8sSectionProps {
  config: AttackSkillConfig
  onConfigChange: (config: AttackSkillConfig) => void
}

const DEFAULTS: K8sSubConfig = {
  registryScan: true,
  rbacEnum: true,
  podBreakout: false,
  etcdExposure: true,
  admissionAudit: false,
  networkPolicy: true,
}

export function ContainerK8sSection({ config, onConfigChange }: ContainerK8sSectionProps) {
  const k8s = { ...DEFAULTS, ...(config.k8sConfig || {}) }

  const toggle = (key: keyof K8sSubConfig, value: boolean) => {
    onConfigChange({
      ...config,
      k8sConfig: { ...k8s, [key]: value },
    })
  }

  return (
    <div className={styles.subSection}>
      <h3 className={styles.subSectionTitle}>Container & K8s Scan Settings</h3>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Registry Image Analysis</span>
          <p className={styles.toggleDescription}>
            Scan container images for known CVEs, leaked secrets, and misconfigured layers
          </p>
        </div>
        <Toggle checked={k8s.registryScan !== false} onChange={(v) => toggle('registryScan', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>RBAC Enumeration</span>
          <p className={styles.toggleDescription}>
            Enumerate Roles, ClusterRoles, RoleBindings, and identify privilege escalation paths
          </p>
        </div>
        <Toggle checked={k8s.rbacEnum !== false} onChange={(v) => toggle('rbacEnum', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Pod Breakout Detection</span>
          <p className={styles.toggleDescription}>
            Assess pod security contexts, hostPath mounts, privileged flags, and capability sets
          </p>
        </div>
        <Toggle checked={k8s.podBreakout === true} onChange={(v) => toggle('podBreakout', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>etcd & API Server Exposure</span>
          <p className={styles.toggleDescription}>
            Check for unauthenticated etcd endpoints, anonymous API access, and insecure ports
          </p>
        </div>
        <Toggle checked={k8s.etcdExposure !== false} onChange={(v) => toggle('etcdExposure', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Admission Controller Audit</span>
          <p className={styles.toggleDescription}>
            Identify mutating/validating webhooks that could be abused for container escape
          </p>
        </div>
        <Toggle checked={k8s.admissionAudit === true} onChange={(v) => toggle('admissionAudit', v)} />
      </div>

      <div className={styles.toggleRow}>
        <div>
          <span className={styles.toggleLabel}>Network Policy Review</span>
          <p className={styles.toggleDescription}>
            Map pod-to-pod communication, identify overly permissive NetworkPolicies, and lateral movement paths
          </p>
        </div>
        <Toggle checked={k8s.networkPolicy !== false} onChange={(v) => toggle('networkPolicy', v)} />
      </div>
    </div>
  )
}

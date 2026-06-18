import { Eye, EyeOff, RotateCw } from 'lucide-react'
import styles from './Settings.module.css'

export interface RotationInfo {
  extraKeyCount: number
  rotateEveryN: number
}

// Badge color mapping
const BADGE_STYLES: Record<string, React.CSSProperties> = {
  'AI Agent': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'var(--status-info-bg)',
    color: 'var(--status-info-text)',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
  'Recon Pipeline': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'var(--status-success-bg)',
    color: 'var(--status-success-text)',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
  'GitHub Secret Hunt': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'rgba(139, 92, 246, 0.12)',
    color: '#8b5cf6',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
  'TruffleHog': {
    display: 'inline-block',
    fontSize: '10px',
    fontWeight: 600,
    padding: '1px 6px',
    borderRadius: '4px',
    background: 'rgba(139, 92, 246, 0.12)',
    color: '#8b5cf6',
    marginLeft: '6px',
    verticalAlign: 'middle',
    letterSpacing: '0.02em',
  },
}

interface SecretFieldProps {
  label: string
  hint: string
  signupUrl?: string
  badges?: string[]
  value: string
  visible: boolean
  onToggle: () => void
  onChange: (v: string) => void
  onConfigureRotation?: () => void
  rotationInfo?: RotationInfo | null
}

export function SecretField({
  label,
  hint,
  signupUrl,
  badges,
  value,
  visible,
  onToggle,
  onChange,
  onConfigureRotation,
  rotationInfo,
}: SecretFieldProps) {
  const mainKeyCount = value && !value.startsWith('••••') ? 1 : value ? 1 : 0
  const totalKeys = mainKeyCount + (rotationInfo?.extraKeyCount || 0)

  return (
    <div className="formGroup">
      <label className="formLabel">
        {label}
        {badges?.map(badge => (
          <span key={badge} style={BADGE_STYLES[badge] || BADGE_STYLES['AI Agent']}>
            {badge}
          </span>
        ))}
      </label>
      <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
        <div className={styles.secretInputWrapper} style={{ flex: 1 }}>
          <input
            className="textInput"
            type={visible ? 'text' : 'password'}
            value={value ?? ''}
            onChange={e => onChange(e.target.value)}
            placeholder={`Enter ${label.toLowerCase()}`}
          />
          <button className={styles.secretToggle} onClick={onToggle} type="button">
            {visible ? <EyeOff size={14} /> : <Eye size={14} />}
          </button>
        </div>
        {onConfigureRotation && (
          <button
            onClick={onConfigureRotation}
            type="button"
            title="Configure key rotation"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              padding: '6px 10px',
              fontSize: '11px',
              fontWeight: 500,
              color: rotationInfo && rotationInfo.extraKeyCount > 0 ? 'var(--accent-secondary)' : 'var(--text-secondary)',
              background: rotationInfo && rotationInfo.extraKeyCount > 0 ? 'var(--accent-secondary-subtle)' : 'var(--bg-tertiary)',
              border: '1px solid var(--border-default)',
              borderRadius: '6px',
              cursor: 'pointer',
              whiteSpace: 'nowrap',
              flexShrink: 0,
            }}
          >
            <RotateCw size={12} />
            Key Rotation
          </button>
        )}
      </div>
      <span className="formHint">
        {hint}
        {signupUrl && (
          <>
            {' — '}
            <a href={signupUrl} target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-primary)' }}>
              Get API key
            </a>
          </>
        )}
      </span>
      {rotationInfo && rotationInfo.extraKeyCount > 0 && (
        <span style={{
          display: 'inline-block',
          fontSize: '10px',
          fontWeight: 600,
          padding: '2px 8px',
          borderRadius: '4px',
          background: 'var(--accent-secondary-subtle)',
          color: 'var(--accent-secondary)',
          marginTop: '4px',
          letterSpacing: '0.02em',
        }}>
          {totalKeys} keys total, rotate every {rotationInfo.rotateEveryN} calls
        </span>
      )}
    </div>
  )
}

'use client'

import { useEffect, useCallback, useRef, ReactNode, KeyboardEvent } from 'react'
import { createPortal } from 'react-dom'
import { X } from 'lucide-react'
import styles from './Modal.module.css'

/** CSS selector for all focusable elements within the modal */
const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

interface ModalProps {
  /** Whether the modal is open */
  isOpen: boolean
  /** Callback when modal should close */
  onClose: () => void
  /** Modal title */
  title?: string
  /** Modal content */
  children: ReactNode
  /** Footer content (typically buttons) */
  footer?: ReactNode
  /** Size variant */
  size?: 'small' | 'default' | 'large' | 'full'
  /** Whether clicking overlay closes the modal */
  closeOnOverlayClick?: boolean
  /** Whether pressing Escape closes the modal */
  closeOnEscape?: boolean
  /** Whether to show the close button */
  showCloseButton?: boolean
  /** Optional actions rendered in the header (between title and close button) */
  headerActions?: ReactNode
}

export function Modal({
  isOpen,
  onClose,
  title,
  children,
  footer,
  size = 'default',
  closeOnOverlayClick = true,
  closeOnEscape = true,
  showCloseButton = true,
  headerActions,
}: ModalProps) {
  const modalRef = useRef<HTMLDivElement>(null)
  const previousActiveElement = useRef<HTMLElement | null>(null)

  // Handle escape key
  const handleKeyDown = useCallback(
    (e: KeyboardEvent<HTMLDivElement>) => {
      if (closeOnEscape && e.key === 'Escape') {
        e.preventDefault()
        onClose()
        return
      }
      // Trap focus within the modal
      if (e.key === 'Tab') {
        const modal = modalRef.current
        if (!modal) return
        const focusable = modal.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)
        if (focusable.length === 0) return
        const first = focusable[0]
        const last = focusable[focusable.length - 1]
        if (e.shiftKey) {
          if (document.activeElement === first) {
            e.preventDefault()
            last.focus()
          }
        } else {
          if (document.activeElement === last) {
            e.preventDefault()
            first.focus()
          }
        }
      }
    },
    [closeOnEscape, onClose],
  )

  // Handle overlay click
  const handleOverlayClick = useCallback(
    (e: React.MouseEvent<HTMLDivElement>) => {
      if (closeOnOverlayClick && e.target === e.currentTarget) {
        onClose()
      }
    },
    [closeOnOverlayClick, onClose]
  )

  // Focus management and body scroll lock
  useEffect(() => {
    if (isOpen) {
      previousActiveElement.current = document.activeElement as HTMLElement

      // Focus the first focusable element inside the modal
      requestAnimationFrame(() => {
        const modal = modalRef.current
        if (!modal) return
        const focusable = modal.querySelector<HTMLElement>(FOCUSABLE_SELECTOR)
        focusable?.focus()
      })

      // Lock body scroll
      document.body.style.overflow = 'hidden'

      return () => {
        document.body.style.overflow = ''
        previousActiveElement.current?.focus()
      }
    }
  }, [isOpen])

  if (!isOpen) return null

  const sizeClass = {
    small: styles.modalSmall,
    default: '',
    large: styles.modalLarge,
    full: styles.modalFull,
  }[size]

  const modalContent = (
    <div
      className={styles.overlay}
      onClick={handleOverlayClick}
      onKeyDown={handleKeyDown}
      role="presentation"
    >
      <div
        ref={modalRef}
        className={`${styles.modal} ${sizeClass}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={title ? 'modal-title' : undefined}
        tabIndex={-1}
      >
        {(title || showCloseButton) && (
          <div className={styles.header}>
            {title && (
              <h2 id="modal-title" className={styles.title}>
                {title}
              </h2>
            )}
            {headerActions && <div style={{ marginLeft: 'auto', marginRight: '8px' }}>{headerActions}</div>}
            {showCloseButton && (
              <button
                type="button"
                className={styles.closeButton}
                onClick={onClose}
                aria-label="Close modal"
              >
                <X size={14} />
              </button>
            )}
          </div>
        )}

        <div className={styles.body}>{children}</div>

        {footer && <div className={styles.footer}>{footer}</div>}
      </div>
    </div>
  )

  // Render in portal
  if (typeof document !== 'undefined') {
    return createPortal(modalContent, document.body)
  }

  return null
}

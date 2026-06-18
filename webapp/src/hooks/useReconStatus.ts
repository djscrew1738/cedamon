'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import type { ReconState, ReconStatus } from '@/lib/recon-types'
import { useToast } from '@/components/ui/Toast/Toast'

interface UseReconStatusOptions {
  projectId: string | null
  enabled?: boolean
  pollingInterval?: number // in milliseconds
  onStatusChange?: (status: ReconStatus) => void
  onComplete?: () => void
  onError?: (error: string) => void
  showToasts?: boolean // auto-show toast notifications on status transitions
}

interface UseReconStatusReturn {
  state: ReconState | null
  isLoading: boolean
  error: string | null
  refetch: () => Promise<void>
  startRecon: () => Promise<ReconState | null>
  stopRecon: () => Promise<ReconState | null>
  pauseRecon: () => Promise<ReconState | null>
  resumeRecon: () => Promise<ReconState | null>
}

const DEFAULT_POLLING_INTERVAL = 5000 // 5 seconds when running
const IDLE_POLLING_INTERVAL = 30000 // 30 seconds when idle (just to catch external changes)

export function useReconStatus({
  projectId,
  enabled = true,
  pollingInterval = DEFAULT_POLLING_INTERVAL,
  onStatusChange,
  onComplete,
  onError,
  showToasts = false,
}: UseReconStatusOptions): UseReconStatusReturn {
  const [state, setState] = useState<ReconState | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const previousStatusRef = useRef<ReconStatus | null>(null)
  const pollingRef = useRef<NodeJS.Timeout | null>(null)

  // Store callbacks in refs to avoid recreating fetchStatus
  const onStatusChangeRef = useRef(onStatusChange)
  const onCompleteRef = useRef(onComplete)
  const onErrorRef = useRef(onError)

  const toast = useToast()

  useEffect(() => {
    onStatusChangeRef.current = onStatusChange
    onCompleteRef.current = onComplete
    onErrorRef.current = onError
  }, [onStatusChange, onComplete, onError])

  const fetchStatus = useCallback(async () => {
    if (!projectId) return

    try {
      const response = await fetch(`/api/recon/${projectId}/status`)
      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to fetch status')
      }

      const data: ReconState = await response.json()
      setState(data)
      setError(null)

      // Check for status transitions (skip firing callbacks for the initial load
      // so a completed scan doesn't re-toast every time the component mounts).
      const prev = previousStatusRef.current
      if (prev !== null && prev !== data.status) {
        onStatusChangeRef.current?.(data.status)

        if (data.status === 'completed') {
          if (showToasts) toast.success('Reconnaissance pipeline completed')
          onCompleteRef.current?.()
        } else if (data.status === 'error' && data.error) {
          if (showToasts) toast.error(`Recon failed: ${data.error}`)
          onErrorRef.current?.(data.error)
        } else if (data.status === 'running' && showToasts) {
          toast.info('Reconnaissance pipeline started')
        } else if (data.status === 'paused' && showToasts) {
          toast.warning('Reconnaissance pipeline paused')
        }
      }

      previousStatusRef.current = data.status

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
    }
  }, [projectId]) // Only depends on projectId now

  const startRecon = useCallback(async (): Promise<ReconState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setError(null)
    if (showToasts) toast.info('Starting reconnaissance pipeline...')

    try {
      const response = await fetch(`/api/recon/${projectId}/start`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to start recon')
      }

      const data: ReconState = await response.json()
      setState(data)
      previousStatusRef.current = data.status
      if (showToasts) toast.success('Reconnaissance pipeline started')
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      onErrorRef.current?.(errorMessage)
      if (showToasts) toast.error(`Failed to start recon: ${errorMessage}`)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const stopRecon = useCallback(async (): Promise<ReconState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    setState(prev => prev ? { ...prev, status: 'stopping' as ReconState['status'] } : prev)
    if (showToasts) toast.info('Stopping reconnaissance pipeline...')

    try {
      const response = await fetch(`/api/recon/${projectId}/stop`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to stop recon')
      }

      const data: ReconState = await response.json()
      setState(data)
      if (showToasts) toast.success('Reconnaissance pipeline stopped')
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      if (showToasts) toast.error(`Failed to stop recon: ${errorMessage}`)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const pauseRecon = useCallback(async (): Promise<ReconState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    if (showToasts) toast.info('Pausing reconnaissance pipeline...')

    try {
      const response = await fetch(`/api/recon/${projectId}/pause`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to pause recon')
      }

      const data: ReconState = await response.json()
      setState(data)
      if (showToasts) toast.warning('Reconnaissance pipeline paused')
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      if (showToasts) toast.error(`Failed to pause recon: ${errorMessage}`)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  const resumeRecon = useCallback(async (): Promise<ReconState | null> => {
    if (!projectId) return null

    setIsLoading(true)
    if (showToasts) toast.info('Resuming reconnaissance pipeline...')

    try {
      const response = await fetch(`/api/recon/${projectId}/resume`, {
        method: 'POST',
      })

      if (!response.ok) {
        const data = await response.json()
        throw new Error(data.error || 'Failed to resume recon')
      }

      const data: ReconState = await response.json()
      setState(data)
      if (showToasts) toast.success('Reconnaissance pipeline resumed')
      return data

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Unknown error'
      setError(errorMessage)
      if (showToasts) toast.error(`Failed to resume recon: ${errorMessage}`)
      return null

    } finally {
      setIsLoading(false)
    }
  }, [projectId])

  // Initial fetch on mount
  useEffect(() => {
    if (!projectId || !enabled) {
      setState(null)
      return
    }

    // Initial fetch only
    fetchStatus()
  }, [projectId, enabled, fetchStatus])

  // Smart polling - only poll frequently when recon is running
  useEffect(() => {
    if (!projectId || !enabled) return

    // Clear any existing polling
    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }

    const isRunning = state?.status === 'running' || state?.status === 'starting' || state?.status === 'paused'

    // Use shorter interval when running, longer when idle
    const interval = isRunning ? pollingInterval : IDLE_POLLING_INTERVAL

    pollingRef.current = setInterval(fetchStatus, interval)

    return () => {
      if (pollingRef.current) {
        clearInterval(pollingRef.current)
        pollingRef.current = null
      }
    }
  }, [projectId, enabled, pollingInterval, fetchStatus, state?.status])

  return {
    state,
    isLoading,
    error,
    refetch: fetchStatus,
    startRecon,
    stopRecon,
    pauseRecon,
    resumeRecon,
  }
}

export default useReconStatus

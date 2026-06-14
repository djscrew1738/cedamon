import { renderHook, waitFor } from '@testing-library/react'
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { useReconStatus } from './useReconStatus'
import type { ReconState } from '@/lib/recon-types'

describe('useReconStatus', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  function mockFetchSequence(states: ReconState[]) {
    let call = 0
    global.fetch = vi.fn().mockImplementation(() => {
      const state = states[Math.min(call, states.length - 1)]
      call += 1
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve(state),
      } as Response)
    })
  }

  it('fires onComplete only when status transitions to completed', async () => {
    const onComplete = vi.fn()
    const states: ReconState[] = [
      {
        project_id: 'p1',
        status: 'running',
        current_phase: null,
        phase_number: null,
        total_phases: 7,
        started_at: null,
        completed_at: null,
        error: null,
      },
      {
        project_id: 'p1',
        status: 'completed',
        current_phase: null,
        phase_number: null,
        total_phases: 7,
        started_at: null,
        completed_at: new Date().toISOString(),
        error: null,
      },
    ]
    mockFetchSequence(states)

    renderHook(() =>
      useReconStatus({
        projectId: 'p1',
        enabled: true,
        pollingInterval: 1000,
        onComplete,
      })
    )

    // Wait for initial fetch
    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1))
    expect(onComplete).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(1500)
    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(onComplete).toHaveBeenCalledTimes(1))
  })

  it('does not fire onComplete when the initial status is already completed', async () => {
    const onComplete = vi.fn()
    const state: ReconState = {
      project_id: 'p1',
      status: 'completed',
      current_phase: null,
      phase_number: null,
      total_phases: 7,
      started_at: null,
      completed_at: new Date().toISOString(),
      error: null,
    }
    mockFetchSequence([state])

    renderHook(() =>
      useReconStatus({
        projectId: 'p1',
        enabled: true,
        pollingInterval: 1000,
        onComplete,
      })
    )

    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1))
    expect(onComplete).not.toHaveBeenCalled()
  })

  it('fires onError when status transitions to error', async () => {
    const onError = vi.fn()
    const states: ReconState[] = [
      {
        project_id: 'p1',
        status: 'running',
        current_phase: null,
        phase_number: null,
        total_phases: 7,
        started_at: null,
        completed_at: null,
        error: null,
      },
      {
        project_id: 'p1',
        status: 'error',
        current_phase: null,
        phase_number: null,
        total_phases: 7,
        started_at: null,
        completed_at: new Date().toISOString(),
        error: 'container crashed',
      },
    ]
    mockFetchSequence(states)

    renderHook(() =>
      useReconStatus({
        projectId: 'p1',
        enabled: true,
        pollingInterval: 1000,
        onError,
      })
    )

    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(1))
    expect(onError).not.toHaveBeenCalled()

    await vi.advanceTimersByTimeAsync(1500)
    await waitFor(() => expect(global.fetch).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(onError).toHaveBeenCalledWith('container crashed'))
  })
})

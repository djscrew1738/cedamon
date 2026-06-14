import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { orchestratorFetch } from './orchestratorFetch'

describe('orchestratorFetch', () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  afterEach(() => {
    vi.restoreAllMocks()
    vi.useRealTimers()
  })

  it('returns the response on success without retries', async () => {
    global.fetch = vi.fn().mockResolvedValue({ status: 200, ok: true } as Response)

    const response = await orchestratorFetch('http://localhost:8010/health')
    expect(response.status).toBe(200)
    expect(global.fetch).toHaveBeenCalledTimes(1)
  })

  it('returns 4xx responses immediately without retrying', async () => {
    global.fetch = vi.fn().mockResolvedValue({ status: 409, ok: false } as Response)

    const response = await orchestratorFetch('http://localhost:8010/recon/p1/start', {
      method: 'POST',
    })
    expect(response.status).toBe(409)
    expect(global.fetch).toHaveBeenCalledTimes(1)
  })

  it('retries on 5xx responses and eventually succeeds', async () => {
    global.fetch = vi
      .fn()
      .mockResolvedValueOnce({ status: 503, ok: false } as Response)
      .mockResolvedValueOnce({ status: 503, ok: false } as Response)
      .mockResolvedValueOnce({ status: 200, ok: true } as Response)

    const promise = orchestratorFetch('http://localhost:8010/recon/p1/status', { retries: 3, retryDelay: 10 })
    await vi.advanceTimersByTimeAsync(200)
    const response = await promise
    expect(response.status).toBe(200)
    expect(global.fetch).toHaveBeenCalledTimes(3)
  })

  it('retries on ECONNREFUSED network errors and eventually succeeds', async () => {
    const error = new Error('fetch failed')
    ;(error as { cause?: { code: string } }).cause = { code: 'ECONNREFUSED' }

    global.fetch = vi
      .fn()
      .mockRejectedValueOnce(error)
      .mockRejectedValueOnce(error)
      .mockResolvedValue({ status: 200, ok: true } as Response)

    const promise = orchestratorFetch('http://localhost:8010/recon/p1/status', { retries: 3, retryDelay: 10 })
    await vi.advanceTimersByTimeAsync(200)
    const response = await promise
    expect(response.status).toBe(200)
    expect(global.fetch).toHaveBeenCalledTimes(3)
  })

  it('returns the last response after exhausting retries on persistent 5xx', async () => {
    global.fetch = vi.fn().mockResolvedValue({ status: 500, ok: false } as Response)

    const promise = orchestratorFetch('http://localhost:8010/recon/p1/status', { retries: 2, retryDelay: 10 })
    await vi.advanceTimersByTimeAsync(200)
    const response = await promise
    expect(response.status).toBe(500)
    expect(global.fetch).toHaveBeenCalledTimes(3)
  })
})

/**
 * Resilient fetch wrapper for calls from the webapp to the recon orchestrator.
 *
 * Retries on transient network errors (ECONNREFUSED, ETIMEDOUT, ENOTFOUND) and
 * 5xx responses with exponential backoff. Non-retryable 4xx responses are
 * returned immediately so callers can surface the correct status code.
 */

const DEFAULT_RETRIES = 3
const BASE_DELAY_MS = 300

function isRetryableError(error: Error): boolean {
  const msg = error.message.toLowerCase()
  if (
    msg.includes('fetch failed') ||
    msg.includes('econnrefused') ||
    msg.includes('etimedout') ||
    msg.includes('enotfound') ||
    msg.includes('eai_again')
  ) {
    return true
  }
  const cause = (error as { cause?: { code?: string } }).cause
  if (cause?.code) {
    const code = cause.code.toLowerCase()
    return (
      code.includes('econnrefused') ||
      code.includes('etimedout') ||
      code.includes('enotfound') ||
      code.includes('eai_again')
    )
  }
  return false
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms))
}

interface OrchestratorFetchOptions extends RequestInit {
  retries?: number
  retryDelay?: number
}

export async function orchestratorFetch(
  url: string,
  options: OrchestratorFetchOptions = {}
): Promise<Response> {
  const { retries = DEFAULT_RETRIES, retryDelay = BASE_DELAY_MS, ...fetchInit } = options

  let lastError: Error | null = null

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await fetch(url, fetchInit)

      // Retry 5xx responses; return 4xx/2xx/3xx immediately.
      if (response.status >= 500 && attempt < retries) {
        lastError = new Error(`Orchestrator returned ${response.status}`)
      } else {
        return response
      }
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error))
      if (!isRetryableError(lastError) || attempt >= retries) {
        throw lastError
      }
    }

    const delay = retryDelay * Math.pow(2, attempt)
    await sleep(delay)
  }

  throw lastError || new Error('Orchestrator request failed after retries')
}

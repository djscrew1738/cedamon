/**
 * API Resilience: fetchWithRetry
 *
 * Thin wrapper around the global `fetch` that retries on network errors
 * and 5xx server errors with exponential backoff.
 *
 * Retry schedule: 200 ms, 400 ms, 800 ms (3 attempts max).
 */

const MAX_RETRIES = 3;

const RETRY_DELAYS_MS = [200, 400, 800];

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Returns `true` when the error is transient and worth retrying.
 */
function isRetryable(error: unknown, status?: number): boolean {
  if (status !== undefined && status >= 500 && status < 600) {
    return true;
  }
  // Network errors (TypeError: Failed to fetch, etc.)
  if (error instanceof TypeError) {
    return true;
  }
  return false;
}

/**
 * Wraps `fetch` with automatic retries and exponential backoff.
 *
 * Only retries on:
 *  - Network errors (TypeError)
 *  - Server errors (5xx)
 *
 * Other HTTP status codes (4xx, 3xx) and successful responses are
 * returned immediately without retrying.
 *
 * @param input   - RequestInfo (URL string or Request object)
 * @param init    - Optional RequestInit
 * @returns       - The first successful Response, or the last error/response
 */
export async function fetchWithRetry(
  input: RequestInfo,
  init?: RequestInit,
): Promise<Response> {
  let lastError: unknown;

  for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
    try {
      const response = await fetch(input, init);

      // Only retry on server errors (5xx)
      if (response.status >= 500 && response.status < 600) {
        lastError = response;
        if (attempt < MAX_RETRIES - 1) {
          await sleep(RETRY_DELAYS_MS[attempt] ?? 800);
          continue;
        }
        return response;
      }

      // Any other status (including 2xx, 3xx, 4xx) — return immediately
      return response;
    } catch (err) {
      lastError = err;
      if (isRetryable(err) && attempt < MAX_RETRIES - 1) {
        await sleep(RETRY_DELAYS_MS[attempt] ?? 800);
        continue;
      }
      throw err;
    }
  }

  // Reached only when all retries exhausted with a retryable response
  throw lastError;
}

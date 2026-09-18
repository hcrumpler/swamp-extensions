/**
 * Shared client helpers for the Atlassian Statuspage API.
 *
 * Provides a thin `fetch` wrapper that injects the `Authorization: OAuth`
 * header required by Statuspage, retries on the 1 req/sec rate limit
 * (HTTP 420/429), and raises descriptive, status-aware errors.
 *
 * @module
 */

/** Base URL for the Statuspage REST API (v1). */
export const STATUSPAGE_BASE_URL = "https://api.statuspage.io/v1";

/** Marker error thrown when the API responds with 404 Not Found. */
export class NotFoundError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NotFoundError";
  }
}

/** Minimal logger surface used by the client (satisfied by swamp's logger). */
export interface ClientLogger {
  info(message: string, properties?: Record<string, unknown>): void;
  warning(message: string, properties?: Record<string, unknown>): void;
}

/** Options accepted by {@link statuspageRequest}. */
export interface RequestOptions {
  /** HTTP method. Defaults to `GET`. */
  method?: "GET" | "POST" | "PATCH" | "DELETE";
  /** API token used for the `Authorization: OAuth <token>` header. */
  apiKey: string;
  /** Request body; serialised as JSON when present. */
  body?: Record<string, unknown>;
  /** Optional cancellation signal. */
  signal?: AbortSignal;
  /** Optional logger for retry diagnostics. */
  logger?: ClientLogger;
  /** Maximum number of attempts on rate-limit responses. Defaults to 5. */
  maxAttempts?: number;
}

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(timer);
      reject(new DOMException("Aborted", "AbortError"));
    }, { once: true });
  });
}

/**
 * Perform a request against the Statuspage API.
 *
 * Retries on HTTP 420/429 (rate limit) with exponential backoff, honouring a
 * `Retry-After` header when present. Throws {@link NotFoundError} on 404 and a
 * descriptive `Error` (including status code and response body) on other
 * non-2xx responses.
 *
 * @typeParam T - Expected shape of the parsed JSON response.
 * @param path - API path beginning with `/` (e.g. `/pages/{id}/components`).
 * @param options - Request configuration including the API key.
 * @returns The parsed JSON response, or `null` for empty (204) responses.
 */
export async function statuspageRequest<T>(
  path: string,
  options: RequestOptions,
): Promise<T> {
  const {
    method = "GET",
    apiKey,
    body,
    signal,
    logger,
    maxAttempts = 5,
  } = options;

  const url = `${STATUSPAGE_BASE_URL}${path}`;
  const baseDelayMs = 1000;
  const maxDelayMs = 30000;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const response = await fetch(url, {
      method,
      headers: {
        Authorization: `OAuth ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
      signal,
    });

    if (response.status === 404) {
      // Drain the body so the connection can be reused.
      await response.text();
      throw new NotFoundError(
        `Statuspage resource not found: ${method} ${path}`,
      );
    }

    // Rate limited — back off and retry.
    if (
      (response.status === 429 || response.status === 420) &&
      attempt < maxAttempts - 1
    ) {
      await response.text();
      const retryAfter = Number(response.headers.get("Retry-After"));
      const backoff = Number.isFinite(retryAfter) && retryAfter > 0
        ? retryAfter * 1000
        : Math.min(baseDelayMs * Math.pow(2, attempt), maxDelayMs);
      const jitter = Math.random() * 0.3 * backoff;
      logger?.warning(
        "Statuspage rate limited, retrying in {waitMs}ms (attempt {attempt})",
        { waitMs: Math.round(backoff + jitter), attempt: attempt + 1 },
      );
      await delay(backoff + jitter, signal);
      continue;
    }

    if (!response.ok) {
      const errorBody = await response.text();
      throw new Error(
        `Statuspage API error ${response.status} on ${method} ${path}: ${errorBody}`,
      );
    }

    // 204 No Content (e.g. component delete) — nothing to parse.
    if (response.status === 204) {
      return null as T;
    }

    const text = await response.text();
    return (text ? JSON.parse(text) : null) as T;
  }

  throw new Error(
    `Statuspage API request failed after ${maxAttempts} attempts: ${method} ${path}`,
  );
}

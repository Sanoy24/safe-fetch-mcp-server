/**
 * Stable, machine-readable failure categories returned to the caller in
 * structuredContent.error.code. Adding a code is fine; renaming or removing one is a
 * breaking change to the tool contract.
 */
export const FETCH_ERROR_CODES = [
  "INVALID_INPUT",
  "POLICY_REJECTED",
  "DNS_RESOLUTION_FAILED",
  "CONNECTION_FAILED",
  "TIMEOUT",
  "REDIRECT_FAILED",
  "INVALID_RESPONSE",
  "PROCESSING_LIMIT",
  "UNSUPPORTED_CONTENT_TYPE",
  "ROBOTS_DISALLOWED",
  "ROBOTS_UNAVAILABLE",
  "INTERNAL_ERROR"
] as const;

export type FetchErrorCode = (typeof FETCH_ERROR_CODES)[number];

// Only transient network conditions are worth retrying. A policy rejection is a
// security decision and must never be retried or worked around.
const RETRYABLE_CODES: ReadonlySet<FetchErrorCode> = new Set([
  "DNS_RESOLUTION_FAILED",
  "CONNECTION_FAILED",
  "TIMEOUT",
  "ROBOTS_UNAVAILABLE"
]);

export function isRetryable(code: FetchErrorCode): boolean {
  return RETRYABLE_CODES.has(code);
}

/**
 * Base class for every refusal raised by the security guard. `message` is shown to
 * the calling model, so it must be actionable and must never contain resolved
 * addresses or raw socket errors. Put that detail in `cause`, which only the
 * stderr audit log prints.
 */
export class GuardError extends Error {
  /** Every URL tried, ending with the refused one. Audit log only: never shown to the model. */
  urlChain?: readonly string[];

  constructor(
    readonly code: FetchErrorCode,
    message: string,
    options?: ErrorOptions
  ) {
    super(message, options);
    this.name = new.target.name;
  }
}

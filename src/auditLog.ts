import type { SafeFetchConfig } from "./config.js";

/**
 * Audit trail (OWASP MCP08:2025): one line per fetch_url outcome, on stderr only
 * (stdout carries MCP traffic in stdio mode). SAFE_FETCH_LOG_FORMAT=json emits one
 * JSON object per line for log pipelines; the default is human-readable key=value.
 *
 * Callers pass already-redacted values. Resolved addresses and socket errors are
 * allowed here (operator-only), but never query-string secrets.
 */
export type AuditFields = Record<string, string | number | boolean | null | undefined>;

function textValue(value: string | number | boolean | null): string {
  const text = String(value);
  return /[\s"=]/.test(text) ? JSON.stringify(text) : text;
}

export function auditLog(
  cfg: Pick<SafeFetchConfig, "logFormat">,
  fields: AuditFields
): void {
  const defined = Object.entries(fields).filter(
    (entry): entry is [string, string | number | boolean | null] => entry[1] !== undefined
  );

  if (cfg.logFormat === "json") {
    console.error(
      JSON.stringify({
        time: new Date().toISOString(),
        event: "fetch_url",
        ...Object.fromEntries(defined)
      })
    );
    return;
  }

  console.error(
    `[fetch_url] ${defined.map(([key, value]) => `${key}=${textValue(value)}`).join(" ")}`
  );
}

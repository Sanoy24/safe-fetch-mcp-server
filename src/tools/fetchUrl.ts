import { z } from "zod";
import { config as defaultConfig, type SafeFetchConfig } from "../config.js";
import {
  safeFetch,
  UrlPolicyError,
  ResolutionError,
  SafeFetchError
} from "../security/index.js";
import { isTextualContentType, toMarkdown } from "../content/toMarkdown.js";

export const FetchUrlInput = z
  .object({
    url: z.string().url().describe("Absolute http(s) URL to fetch."),
    format: z
      .enum(["markdown", "raw"])
      .default("markdown")
      .describe("Output format. 'markdown' (default) or 'raw' text."),
    max_bytes: z
      .number()
      .int()
      .positive()
      .optional()
      .describe("Override the max response size for this call."),
    start_index: z
      .number()
      .int()
      .min(0)
      .default(0)
      .describe("Byte offset for chunked reading of long pages.")
  })
  .strict();

export type FetchUrlInput = z.infer<typeof FetchUrlInput>;

export interface FetchUrlStructuredContent {
  readonly status: number;
  readonly finalUrl: string;
  readonly contentType: string;
  readonly bytes: number;
  readonly truncated: boolean;
  readonly [key: string]: unknown;
}

export interface FetchUrlToolResult {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: FetchUrlStructuredContent;
  isError?: boolean;
  [key: string]: unknown;
}

function isRefusal(err: unknown): err is UrlPolicyError | ResolutionError | SafeFetchError {
  return (
    err instanceof UrlPolicyError || err instanceof ResolutionError || err instanceof SafeFetchError
  );
}

export async function runFetchUrl(
  rawArgs: unknown,
  baseConfig: SafeFetchConfig = defaultConfig
): Promise<FetchUrlToolResult> {
  let input: FetchUrlInput;
  try {
    input = FetchUrlInput.parse(rawArgs);
  } catch {
    return {
      isError: true,
      content: [{ type: "text", text: "Refused: invalid input for fetch_url." }]
    };
  }

  const cfg: SafeFetchConfig =
    input.max_bytes !== undefined ? { ...baseConfig, maxBytes: input.max_bytes } : baseConfig;

  try {
    const result = await safeFetch(input.url, cfg);

    const text =
      input.format === "raw" || !isTextualContentType(result.contentType)
        ? result.body.toString("utf-8")
        : toMarkdown(result.body, result.contentType);

    const sliced = input.start_index > 0 ? text.slice(input.start_index) : text;

    return {
      content: [{ type: "text", text: sliced }],
      structuredContent: {
        status: result.status,
        finalUrl: result.finalUrl,
        contentType: result.contentType,
        bytes: result.body.byteLength,
        truncated: result.truncated
      }
    };
  } catch (err) {
    if (isRefusal(err)) {
      return { isError: true, content: [{ type: "text", text: err.message }] };
    }
    return {
      isError: true,
      content: [{ type: "text", text: "Refused: the request could not be completed." }]
    };
  }
}

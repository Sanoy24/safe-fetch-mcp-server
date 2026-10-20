---
name: writing-mcp-servers
description: Best practices for writing MCP server tools in TypeScript (current SDK). Use when adding or editing a tool, its schema, description, annotations, error handling, or response format in this repo.
---

# Writing MCP Server Tools (TypeScript)

Follow these when creating or editing any tool. They reflect the current MCP TypeScript SDK
conventions — do not fall back to older patterns.

## Use modern SDK APIs only

- **Do use**: `server.registerTool()`, `server.registerResource()`, `server.registerPrompt()`.
- **Do NOT use**: `server.tool()`, or manual `server.setRequestHandler(ListToolsRequestSchema, ...)`.
  The `register*` methods give type safety and automatic schema handling.

Initialize once:

```ts
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
const server = new McpServer({
  name: "safe-fetch-mcp-server",
  version: "0.1.0"
});
```

## Tool naming

- snake_case, action-oriented, service-prefixed to avoid collisions with other servers.
- This repo's tool is `fetch_url` (and optionally `fetch_raw`). No version numbers in names.

## Input schemas: Zod, strict, described

- Every input schema is a Zod object with `.strict()` (reject unknown keys).
- Every field has constraints and a `.describe()`.
- Derive the TypeScript type from the schema with `z.infer`.

```ts
import { z } from "zod";

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
      .describe("Lower the max response size (bytes). Cannot exceed the server limit."),
    start_index: z
      .number()
      .int()
      .min(0)
      .default(0)
      .describe("Character offset into the converted text; pass nextStartIndex to page.")
  })
  .strict();

export type FetchUrlInput = z.infer<typeof FetchUrlInput>;
```

## Register with title, description, inputSchema, annotations

- The `description` is what the agent reads — make it precise and matched to actual behavior.
  Include args, return shape, and 1–2 usage examples. JSDoc is NOT auto-extracted.
- Annotations for a read-only fetch tool:
  `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: true`.

```ts
server.registerTool(
  "fetch_url",
  {
    title: "Fetch URL",
    description:
      "Fetch a public http(s) URL and return markdown. Read-only; refuses private/loopback/metadata targets. Args: url, format, max_chars, start_index, max_bytes. Returns text plus structuredContent {status, finalUrl, ..., nextStartIndex}; on failure structuredContent.error {code, retryable, message}.",
    inputSchema: FetchUrlInput,
    annotations: {
      readOnlyHint: true,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: true
    }
  },
  async (params: FetchUrlInput) => {
    /* call the single hardened fetch function; see security skill */
  }
);
```

## Responses: text + structuredContent

Return both a human-readable text block and machine-readable `structuredContent`:

```ts
const output = { status, finalUrl, contentType, bytes, truncated };
return {
  content: [{ type: "text", text: markdown }],
  structuredContent: output
};
```

## Errors: in-result, actionable, non-leaky

- Report tool errors inside the result with `isError: true`, not as protocol errors.
- Build every error result with the shared `errorResult(code, message)` in
  `src/tools/fetchUrl.ts`. It sets `structuredContent.error = { code, retryable, message }`.
  Codes are defined once in `src/security/errors.ts`; adding one is fine, renaming or
  removing one breaks the contract.
- Guard failures throw a `GuardError` subclass carrying its code. Don't map error
  message strings to codes.
- Messages must be actionable and must never contain resolved IPs, raw socket errors,
  stack traces or internal paths (threat-model row 15). Put that detail in the
  error's `cause`, which only the stderr audit log prints.

```ts
throw new ResolutionError(
  "POLICY_REJECTED",
  `Refused: "${hostname}" resolves to a private or non-public address. ` +
    "Set SAFE_FETCH_ALLOW_LOCAL=true only for trusted local targets.",
  { cause: `resolved address=${addr.address}` }
);
```

## Output schema

**`structuredContent` must be self-sufficient.** Some clients (Claude Code, observed
2026-10-20) show the model _only_ `structuredContent` when it is present, and drop the text
content block, with or without an `outputSchema`. Anything the agent needs goes in
`structuredContent` too: the framed page `text` on success, and the `message` on errors.
This bug shipped in 0.2.0–0.4.0. Agents received metadata but no page, and only an
end-to-end check through a real client caught it. `test/toolContract.spec.ts` ("structured-only
clients") guards it now.

`fetch_url` declares `outputSchema: FetchUrlOutput`. Every field is optional so that both
success and error `structuredContent` conform. When you add a field, add it to the
schema with a `.describe()`, and extend the conformance test in
`test/toolContract.spec.ts`.

## Transports

- `stdio` by default (local). **Log to stderr only** (`console.error`); stdout is MCP traffic.
- Streamable HTTP (stateless JSON) for remote: a new transport per request,
  `sessionIdGenerator: undefined`, `enableJsonResponse: true`. Avoid deprecated SSE.
- For local HTTP: validate `Origin`, enable DNS-rebinding protection, bind `127.0.0.1`.

## Code quality

- Strict TypeScript, no `any` (use `unknown` + type guards).
- Explicit `Promise<T>` return types on async functions.
- DRY: one shared fetch function, one shared error formatter. Never duplicate the security
  guard — a duplicated/second fetch path is how SSRF guards get bypassed.

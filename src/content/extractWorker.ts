import { parentPort } from "node:worker_threads";
import { extractContent, type ExtractMode } from "./extract.js";
import type { ImageMode } from "./sanitize.js";

/**
 * Worker-thread entry for page processing. Conversion runs on attacker-controlled input
 * and can take arbitrarily long, so it must be killable: see extractPool.ts.
 * Pure CPU work on bytes already fetched; this thread never touches the network.
 */
export interface ExtractJob {
  readonly body: Uint8Array;
  readonly contentType: string;
  readonly mode: ExtractMode;
  readonly baseUrl?: string;
  readonly images?: ImageMode;
}

parentPort?.on("message", (job: ExtractJob) => {
  const body = Buffer.from(job.body.buffer, job.body.byteOffset, job.body.byteLength);
  parentPort?.postMessage(
    extractContent(body, job.contentType, job.mode, job.baseUrl, job.images)
  );
});

// Loading the parsers takes most of a second, and that shouldn't use up a page's budget.
parentPort?.postMessage("ready");

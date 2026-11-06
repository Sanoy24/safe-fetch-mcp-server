import { Worker } from "node:worker_threads";
import { GuardError } from "../security/errors.js";
import type { ExtractedContent } from "./extract.js";
import type { ExtractJob } from "./extractWorker.js";

/**
 * Runs page processing in a small pool of worker threads with a hard time limit
 * (threat-model row 26). A hostile page can't block the server: the event loop stays
 * free, and a job over budget has its thread terminated. The pool size also caps how
 * much CPU concurrent fetches can use for parsing.
 */
const MAX_WORKERS = 4;
const WORKER_MEMORY_MB = 512;

interface PendingJob {
  readonly input: ExtractJob;
  readonly resolve: (value: ExtractedContent) => void;
  readonly reject: (err: Error) => void;
  timer?: NodeJS.Timeout;
  worker?: Worker;
  detach?: () => void;
}

const idle: Worker[] = [];
const queue: PendingJob[] = [];
let workerCount = 0;

// Workers need compiled JavaScript. Under vitest this module runs from src/, so it uses
// dist/ (npm test builds first).
function workerUrl(): URL {
  return import.meta.url.endsWith(".ts")
    ? new URL("../../dist/content/extractWorker.js", import.meta.url)
    : new URL("./extractWorker.js", import.meta.url);
}

function limitError(cause: string): GuardError {
  return new GuardError(
    "PROCESSING_LIMIT",
    "Refused: the page is too large or complex to convert within the limits. Try format: 'raw' or a lower max_bytes.",
    { cause }
  );
}

function discard(worker: Worker): void {
  workerCount -= 1;
  void worker.terminate();
}

function pump(): void {
  while (queue.length > 0) {
    let worker = idle.pop();
    if (!worker && workerCount < MAX_WORKERS) {
      worker = new Worker(workerUrl(), {
        resourceLimits: { maxOldGenerationSizeMb: WORKER_MEMORY_MB }
      });
      worker.unref(); // an idle worker must never keep the process alive
      workerCount += 1;
    }
    if (!worker) return;
    run(worker, queue.shift() as PendingJob);
  }
}

function run(worker: Worker, job: PendingJob): void {
  job.worker = worker;
  const onMessage = (result: ExtractedContent): void => {
    job.detach?.();
    idle.push(worker);
    job.resolve(result);
    pump();
  };
  const onError = (err: Error): void => {
    job.detach?.();
    discard(worker);
    job.reject(limitError(`worker failed: ${err.message}`));
    pump();
  };
  // Remove only our own handlers: removeAllListeners() also strips the Worker's internal
  // ones, and a reused worker then never delivers another message.
  job.detach = (): void => {
    clearTimeout(job.timer);
    worker.off("message", onMessage);
    worker.off("error", onError);
  };
  worker.on("message", onMessage);
  worker.on("error", onError);
  worker.postMessage(job.input);
}

/** Converts a fetched body off the main thread, rejecting once budgetMs has passed. */
export function extractInWorker(
  input: ExtractJob,
  budgetMs: number
): Promise<ExtractedContent> {
  return new Promise((resolve, reject) => {
    const job: PendingJob = { input, resolve, reject };
    // The clock starts now, so time spent queued counts against the budget too.
    job.timer = setTimeout(() => {
      if (job.worker) {
        job.detach?.();
        discard(job.worker);
      } else {
        queue.splice(queue.indexOf(job), 1);
      }
      reject(limitError(`processing exceeded ${budgetMs}ms`));
      pump();
    }, budgetMs);
    queue.push(job);
    pump();
  });
}

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
const MAX_QUEUE_WAIT_MS = 30_000;
// Queued jobs hold their whole fetched body in memory, so the queue is bounded too.
const MAX_QUEUED_JOBS = 32;

interface PendingJob {
  readonly input: ExtractJob;
  readonly budgetMs: number;
  readonly resolve: (value: ExtractedContent) => void;
  readonly reject: (err: Error) => void;
  queueTimer?: NodeJS.Timeout;
}

const idle: Worker[] = [];
const queue: PendingJob[] = [];
let workerCount = 0;
let busyCount = 0;

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

function startWorker(): void {
  const worker = new Worker(workerUrl(), {
    resourceLimits: { maxOldGenerationSizeMb: WORKER_MEMORY_MB }
  });
  worker.unref(); // an idle worker must never keep the process alive
  workerCount += 1;

  const onStartupError = (err: Error): void => {
    worker.off("message", onReady);
    discard(worker);
    // A worker that can't start won't start on retry, so don't leave jobs waiting.
    for (const job of queue.splice(0)) {
      clearTimeout(job.queueTimer);
      job.reject(limitError(`worker failed to start: ${err.message}`));
    }
  };
  const onReady = (): void => {
    worker.off("error", onStartupError);
    idle.push(worker);
    pump();
  };
  worker.once("message", onReady);
  worker.once("error", onStartupError);
}

function pump(): void {
  while (queue.length > 0 && idle.length > 0) {
    run(idle.pop() as Worker, queue.shift() as PendingJob);
  }
  // Start workers for jobs that no already-starting worker will take.
  const starting = workerCount - idle.length - busyCount;
  for (let i = starting; i < queue.length && workerCount < MAX_WORKERS; i += 1) {
    startWorker();
  }
}

function run(worker: Worker, job: PendingJob): void {
  clearTimeout(job.queueTimer);
  busyCount += 1;
  // Remove only our own handlers: removeAllListeners() also strips the Worker's internal
  // ones, and a reused worker then never delivers another message.
  const detach = (): void => {
    busyCount -= 1;
    clearTimeout(timer);
    worker.off("message", onMessage);
    worker.off("error", onError);
  };
  const onMessage = (result: ExtractedContent): void => {
    detach();
    idle.push(worker);
    job.resolve(result);
    pump();
  };
  const onError = (err: Error): void => {
    detach();
    discard(worker);
    job.reject(limitError(`worker failed: ${err.message}`));
    pump();
  };
  const timer = setTimeout(() => {
    detach();
    discard(worker);
    job.reject(limitError(`processing exceeded ${job.budgetMs}ms`));
    pump();
  }, job.budgetMs);
  worker.on("message", onMessage);
  worker.on("error", onError);
  worker.postMessage(job.input);
}

/**
 * Converts a fetched body off the main thread. budgetMs is the time for this page once a
 * ready worker has it; waiting for a free worker is capped separately.
 */
export function extractInWorker(
  input: ExtractJob,
  budgetMs: number
): Promise<ExtractedContent> {
  if (queue.length >= MAX_QUEUED_JOBS) {
    return Promise.reject(
      new GuardError(
        "PROCESSING_LIMIT",
        "Refused: the server is busy converting other pages. Try again shortly."
      )
    );
  }
  return new Promise((resolve, reject) => {
    const job: PendingJob = { input, budgetMs, resolve, reject };
    job.queueTimer = setTimeout(() => {
      queue.splice(queue.indexOf(job), 1);
      reject(limitError(`no worker became free within ${MAX_QUEUE_WAIT_MS}ms`));
    }, MAX_QUEUE_WAIT_MS);
    queue.push(job);
    pump();
  });
}

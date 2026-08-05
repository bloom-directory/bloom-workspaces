import { randomUUID } from "node:crypto";
import { GuestRequest, type GuestRequest as GuestRequestValue } from "../guest-protocol.js";
import { JobStatus, MAX_JOB_LOG_CHUNK_BYTES, StructuredJobSpec, type JobStatus as JobStatusValue, type StructuredJobSpec as StructuredJobSpecValue } from "./model.js";

export type GuestRequestCall = (request: GuestRequestValue, timeoutMs?: number) => Promise<unknown>;

/**
 * Thin orchestration client for the isolated guest job engine. Authentication
 * and workspace ownership stay at the HTTP integration boundary; this class
 * only emits the bounded, structured guest protocol and validates every reply.
 */
export class GuestJobs {
  constructor(private readonly call: GuestRequestCall) {}

  async start(input: StructuredJobSpecValue, jobId = randomUUID()): Promise<JobStatusValue> {
    const spec = StructuredJobSpec.parse(input);
    const request = GuestRequest.parse({
      version: 1,
      id: requestId(),
      operation: "job.start",
      jobId,
      argv: spec.argv,
      cwd: spec.cwd,
      environment: spec.environment,
      timeoutMs: spec.timeoutMs,
    });
    return JobStatus.parse(await this.call(request, 10_000));
  }

  async status(jobId: string, logOffset = 0, maxBytes = MAX_JOB_LOG_CHUNK_BYTES): Promise<JobStatusValue> {
    const request = GuestRequest.parse({ version: 1, id: requestId(), operation: "job.status", jobId, logOffset, maxBytes });
    return JobStatus.parse(await this.call(request, 10_000));
  }

  async cancel(jobId: string): Promise<JobStatusValue> {
    const request = GuestRequest.parse({ version: 1, id: requestId(), operation: "job.cancel", jobId });
    return JobStatus.parse(await this.call(request, 10_000));
  }
}

function requestId() {
  return `job_${randomUUID().replaceAll("-", "")}`;
}

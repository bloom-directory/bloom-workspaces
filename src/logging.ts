import { randomUUID } from "node:crypto";
import type { NextFunction, Request, Response } from "express";

/**
 * Structured request logging middleware.
 *
 * Assigns a unique request ID, measures latency, and emits a JSON line to
 * stdout for every HTTP response. The request ID is exposed via the
 * `x-request-id` response header so operators can correlate client reports
 * with server logs.
 */
export function requestLogger(prefix: string) {
  return (request: Request, response: Response, next: NextFunction) => {
    const requestId = (request.headers["x-request-id"] as string | undefined)?.slice(0, 64) || randomUUID();
    response.setHeader("x-request-id", requestId);
    const started = Date.now();
    response.on("finish", () => {
      const duration = Date.now() - started;
      const { method } = request;
      const url = request.originalUrl ?? request.url ?? "";
      const { statusCode } = response;
      // Skip health-check noise unless it fails.
      if (url === "/healthz" && statusCode === 200) return;
      const level = statusCode >= 500 ? "error" : statusCode >= 400 ? "warn" : "info";
      const payload = JSON.stringify({
        ts: new Date().toISOString(),
        level,
        component: prefix,
        requestId,
        method,
        url,
        statusCode,
        durationMs: duration,
      });
      if (level === "error") console.error(payload);
      else console.log(payload);
    });
    next();
  };
}

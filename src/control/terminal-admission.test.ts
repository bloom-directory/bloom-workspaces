import { describe, expect, it } from "vitest";
import { TerminalAdmission } from "./terminal-admission.js";

describe("terminal admission", () => {
  it("bounds each workspace and the global socket count", () => {
    const admission = new TerminalAdmission(2, 3);
    const releaseA1 = admission.acquire("a");
    const releaseA2 = admission.acquire("a");
    expect(releaseA1).toBeTypeOf("function");
    expect(releaseA2).toBeTypeOf("function");
    expect(admission.acquire("a")).toBeUndefined();
    const releaseB = admission.acquire("b");
    expect(releaseB).toBeTypeOf("function");
    expect(admission.acquire("c")).toBeUndefined();
    releaseA1?.();
    releaseA1?.();
    expect(admission.acquire("c")).toBeTypeOf("function");
  });
});

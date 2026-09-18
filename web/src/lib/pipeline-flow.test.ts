import { describe, expect, it } from "vitest";
import { DECIDED_BY, RAIL, SANDBOX_LIVE, STAGES, between, locate, stageStart, typed } from "./pipeline-flow";

describe("pipeline flow", () => {
  it("has the six scroll stages in order, with steps 4 and 5 sharing the parallel stage", () => {
    expect(STAGES.map((s) => s.id)).toEqual(["fetch", "intel", "info", "fork", "ai", "verdict"]);
    expect(RAIL.map((r) => r.n)).toEqual([1, 2, 3, 4, 5, 6, 7]);
    expect(RAIL.filter((r) => r.stage === "fork").map((r) => r.lane)).toEqual(["static", "sandbox"]);
  });

  it("locates progress inside the right stage", () => {
    expect(locate(0)).toEqual({ index: 0, t: 0 });
    expect(locate(1).index).toBe(STAGES.length - 1);
    expect(locate(1).t).toBe(1);
    const mid = locate(stageStart(3) + 0.001);
    expect(mid.index).toBe(3);
  });

  it("clamps out-of-range progress", () => {
    expect(locate(-5).index).toBe(0);
    expect(locate(9).index).toBe(STAGES.length - 1);
  });

  it("types text progressively", () => {
    expect(typed("abcd", 0, 0.2, 0.8)).toBe("");
    expect(typed("abcd", 0.5, 0.2, 0.8)).toBe("ab");
    expect(typed("abcd", 1, 0.2, 0.8)).toBe("abcd");
    expect(between(0.5, 0, 1)).toBe(0.5);
  });

  it("exposes the flag that toggles the in-development badge", () => {
    expect(typeof SANDBOX_LIVE).toBe("boolean");
  });

  it("lists sandbox proof as a final, non-overridable decider", () => {
    const sandbox = DECIDED_BY.find((d) => d.id === "sandbox");
    expect(sandbox?.note).toMatch(/cannot be overridden/);
  });
});

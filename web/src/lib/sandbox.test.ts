import { describe, expect, it } from "vitest";
import cleanReport from "../../../schema/examples/sandbox-clean/report.json";
import exfilReport from "../../../schema/examples/sandbox-malicious-exfil/report.json";
import gateReport from "../../../schema/examples/sandbox-conditional-ci-gate/report.json";
import dropperReport from "../../../schema/examples/sandbox-dropper/report.json";
import persistReport from "../../../schema/examples/sandbox-persistence/report.json";
import type { SandboxReport } from "@/lib/types/domain";
import { DECIDED_BY_LABEL } from "@/lib/verdict";
import {
  classificationInfo,
  coverageGaps,
  coverageLine,
  groupFiles,
  hasProof,
  hostileOnlyHosts,
  isPersistencePath,
  mergeFiles,
  processTree,
  sandboxStage,
  sortedNetwork,
  statusHeadline,
} from "./sandbox";

const sb = (r: unknown) => (r as { sandbox: SandboxReport }).sandbox;

describe("sandbox stage summary", () => {
  it("says not run when there is no sandbox report", () => {
    expect(sandboxStage(null)).toMatchObject({ headline: "Not run", tone: "muted" });
    expect(statusHeadline(undefined)).toBe("Not run");
  });

  it("is bad on proof-grade findings and names what ran", () => {
    const stage = sandboxStage(sb(exfilReport));
    expect(stage.headline).toBe("Complete");
    expect(stage.tone).toBe("bad");
    expect(stage.detail).toMatch(/2 runs/);
  });

  it("is warn on MEDIUM findings without HIGH ones", () => {
    const only = { ...sb(dropperReport), findings: (sb(dropperReport).findings ?? []).filter((f) => f.severity === "MEDIUM") };
    expect(sandboxStage(only).tone).toBe("warn");
  });

  it("does not turn a quiet result on code that never loaded into an all-clear", () => {
    const quiet: SandboxReport = { ...sb(cleanReport), coverage: { ...sb(cleanReport).coverage!, entryLoaded: false } };
    expect(sandboxStage(quiet).tone).toBe("muted");
    expect(sandboxStage(sb(cleanReport)).tone).toBe("ok");
  });

  it("shows failed and skipped as muted with the reason", () => {
    const failed: SandboxReport = { ...sb(cleanReport), status: "FAILED", skipReason: "task timed out" };
    expect(sandboxStage(failed)).toMatchObject({ headline: "Failed", detail: "task timed out", tone: "muted" });
  });

  it("builds the coverage line from real fields", () => {
    const withDeps: SandboxReport = {
      ...sb(cleanReport),
      coverage: { ...sb(cleanReport).coverage!, dependenciesProvided: true, dependenciesCount: 64, binsRun: 2 },
    };
    expect(coverageLine(withDeps)).toBe("2 runs, entry loaded, 64 dependencies, 2 bins run");
  });
});

describe("coverage gaps", () => {
  it("explains why a run could not be fully observed", () => {
    const gaps = coverageGaps(sb(exfilReport));
    expect(gaps.some((g) => g.startsWith("The main file did not load"))).toBe(true);
    expect(gaps.join(" ")).toMatch(/Dependencies were left out/);
  });
  it("has nothing to say for a fully observed clean run except stripped dependencies", () => {
    expect(coverageGaps(sb(cleanReport)).every((g) => /Dependencies/.test(g))).toBe(true);
  });
});

describe("network", () => {
  it("orders the normal run before the hostile run", () => {
    const runs = sortedNetwork(sb(exfilReport)).map((n) => n.run);
    expect(runs.indexOf("hostile")).toBeGreaterThan(runs.lastIndexOf("baseline") - 1);
    expect(runs[0]).toBe("baseline");
  });
  it("labels host classes and never uses color alone", () => {
    expect(classificationInfo("oast")).toEqual({ label: "Request-capture service", tone: "bad" });
    expect(classificationInfo("expected").tone).toBe("muted");
  });
  it("finds hosts contacted only under hostile conditions", () => {
    expect(hostileOnlyHosts(sb(gateReport)).length).toBeGreaterThan(0);
  });
  it("marks canary hits as proof", () => {
    expect(hasProof(sb(exfilReport))).toBe(true);
    expect(hasProof(sb(cleanReport))).toBe(false);
  });
});

describe("processes", () => {
  it("nests children under their parent", () => {
    const tree = processTree(sb(exfilReport), "baseline");
    expect(tree[0].depth).toBe(0);
    expect(tree.some((n) => n.depth === 1)).toBe(true);
  });
});

describe("files", () => {
  it("calls out persistence writes and dropped executables", () => {
    expect(isPersistencePath("/home/sandbox/.bashrc")).toBe(true);
    expect(isPersistencePath("/tmp/data.json")).toBe(false);
    expect(groupFiles(sb(persistReport))[0].id).toBe("persistence");
    expect(groupFiles(sb(dropperReport)).some((g) => g.id === "dropped")).toBe(true);
  });
});

describe("merged files", () => {
  it("shows one row when both runs made the same change", () => {
    const merged = mergeFiles(sb(persistReport).files ?? []);
    expect(merged.length).toBeLessThan((sb(persistReport).files ?? []).length);
    expect(merged.some((f) => f.runs.length === 2)).toBe(true);
  });
});

describe("wording", () => {
  it("names the sandbox as the decider", () => {
    expect(DECIDED_BY_LABEL.sandbox).toBe("Confirmed by sandbox run");
  });
});

import type {
  Finding,
  SandboxFileEvent,
  SandboxNetworkEvent,
  SandboxProcess,
  SandboxReport,
} from "@/lib/types/domain";

export type Tone = "ok" | "warn" | "bad" | "muted";

const STATUS_HEADLINE: Record<string, string> = {
  COMPLETE: "Complete",
  PARTIAL: "Partial",
  FAILED: "Failed",
  SKIPPED: "Skipped",
  NOT_RUN: "Not run",
};

export function statusHeadline(sb?: SandboxReport | null): string {
  return sb ? (STATUS_HEADLINE[sb.status] ?? "Not run") : "Not run";
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** "2 runs, entry loaded, 64 dependencies": what was actually observed. */
export function coverageLine(sb: SandboxReport): string {
  const parts: string[] = [];
  parts.push(plural(sb.runs?.length ?? 0, "run"));
  const c = sb.coverage;
  if (c) {
    if (c.entryLoaded === true) parts.push("entry loaded");
    else if (c.entryLoaded === false) parts.push("entry not loaded");
    if (c.dependenciesProvided && (c.dependenciesCount ?? 0) > 0) parts.push(plural(c.dependenciesCount ?? 0, "dependency", "dependencies"));
    else if (c.dependenciesStripped) parts.push("dependencies stripped");
    if ((c.binsRun ?? 0) > 0) parts.push(`${plural(c.binsRun ?? 0, "bin")} run`);
  }
  return parts.join(", ");
}

export function severityCounts(findings: Finding[] = []) {
  return {
    high: findings.filter((f) => f.severity === "HIGH").length,
    medium: findings.filter((f) => f.severity === "MEDIUM").length,
    low: findings.filter((f) => f.severity === "LOW").length,
  };
}

/** The "Sandbox" step of the check trace: headline is the status, the tone follows the findings. */
export function sandboxStage(sb?: SandboxReport | null): { headline: string; detail: string; tone: Tone } {
  if (!sb || sb.status === "NOT_RUN") {
    return { headline: "Not run", detail: "No dynamic analysis on this scan", tone: "muted" };
  }
  const headline = statusHeadline(sb);
  if (sb.status === "FAILED" || sb.status === "SKIPPED") {
    return { headline, detail: sb.skipReason ?? "The sandbox could not run", tone: "muted" };
  }
  const { high, medium } = severityCounts(sb.findings ?? []);
  const detail = coverageLine(sb);
  if (high > 0) return { headline, detail, tone: "bad" };
  if (medium > 0) return { headline, detail, tone: "warn" };
  if (sb.status === "PARTIAL") return { headline, detail, tone: "warn" };
  // A quiet result on code that never loaded must not read as an all-clear.
  if (sb.coverage?.entryLoaded === false) return { headline, detail, tone: "muted" };
  return { headline, detail, tone: "ok" };
}

/** Plain-language reasons the recording may be incomplete, so a clean result is never overstated. */
export function coverageGaps(sb: SandboxReport): string[] {
  const c = sb.coverage;
  const gaps: string[] = [];
  if (!c) return gaps;
  if (!c.installed) gaps.push("The package did not finish installing.");
  if (c.entryLoaded === false) {
    const why = (c.entryError ?? "").split("\n")[0].trim();
    gaps.push(`The main file did not load${why ? `: ${why}` : "."}`);
  }
  if (c.timedOut) gaps.push("A phase hit the time limit before it finished.");
  if (c.dependenciesStripped && !c.dependenciesProvided) gaps.push("Dependencies were left out, so code that needs them may stop early.");
  if (c.dependenciesNote) gaps.push(c.dependenciesNote);
  return gaps;
}

// --- network ---------------------------------------------------------------

export function classificationInfo(c: SandboxNetworkEvent["classification"]): { label: string; tone: Tone } {
  switch (c) {
    case "expected":
      return { label: "Expected", tone: "muted" };
    case "unexpected":
      return { label: "Unexpected host", tone: "warn" };
    case "oast":
      return { label: "Request-capture service", tone: "bad" };
    case "webhook":
      return { label: "Chat webhook", tone: "bad" };
    case "paste":
      return { label: "Paste site", tone: "warn" };
    case "tunnel":
      return { label: "Tunnel", tone: "bad" };
    case "metadata":
      return { label: "Cloud metadata", tone: "bad" };
    case "stratum":
      return { label: "Mining pool", tone: "bad" };
    case "raw_ip":
      return { label: "Raw IP address", tone: "warn" };
  }
}

const RUN_ORDER = (run: string) => (run === "baseline" ? 0 : 1);

export function runLabel(run: string): string {
  return run === "baseline" ? "Run A · normal" : run === "hostile" ? "Run B · hostile" : run;
}

export function sortedNetwork(sb: SandboxReport): SandboxNetworkEvent[] {
  return [...(sb.network ?? [])].sort((a, b) => RUN_ORDER(a.run) - RUN_ORDER(b.run));
}

/** Hosts contacted only under hostile conditions. */
export function hostileOnlyHosts(sb: SandboxReport): string[] {
  const base = new Set((sb.network ?? []).filter((n) => n.run === "baseline").map((n) => n.host ?? n.ip ?? ""));
  const out = new Set<string>();
  for (const n of sb.network ?? []) {
    const host = n.host ?? n.ip ?? "";
    if (n.run !== "baseline" && host && !base.has(host)) out.add(host);
  }
  return [...out];
}

// --- processes -------------------------------------------------------------

export type ProcessNode = { proc: SandboxProcess; depth: number };

/** Parent/child order for one run, each process tagged with its depth. */
export function processTree(sb: SandboxReport, run: string): ProcessNode[] {
  const procs = (sb.processes ?? []).filter((p) => p.run === run);
  const pids = new Set(procs.map((p) => p.pid));
  const children = new Map<number, SandboxProcess[]>();
  const roots: SandboxProcess[] = [];
  for (const p of procs) {
    if (p.ppid != null && pids.has(p.ppid) && p.ppid !== p.pid) {
      const list = children.get(p.ppid) ?? [];
      list.push(p);
      children.set(p.ppid, list);
    } else {
      roots.push(p);
    }
  }
  const out: ProcessNode[] = [];
  const seen = new Set<number>();
  const walk = (p: SandboxProcess, depth: number) => {
    if (seen.has(p.pid)) return;
    seen.add(p.pid);
    out.push({ proc: p, depth });
    for (const c of children.get(p.pid) ?? []) walk(c, depth + 1);
  };
  for (const r of roots) walk(r, 0);
  return out;
}

export function runsPresent(sb: SandboxReport): string[] {
  const names = new Set<string>();
  for (const r of sb.runs ?? []) names.add(r.name);
  for (const p of sb.processes ?? []) names.add(p.run);
  return [...names].sort((a, b) => RUN_ORDER(a) - RUN_ORDER(b));
}

// --- files -----------------------------------------------------------------

const PERSISTENCE = /(\.bashrc|\.bash_profile|\.profile|\.zshrc|\.zprofile|crontab|authorized_keys|\/systemd\/|LaunchAgents|LaunchDaemons|rc\.local|\.ssh\/config)/i;

export function isPersistencePath(path: string): boolean {
  return PERSISTENCE.test(path);
}

export type FileGroupId = "persistence" | "dropped" | "decoy" | "other";

export const FILE_GROUP_LABEL: Record<FileGroupId, string> = {
  persistence: "Persistence: written to survive a reboot or a new shell",
  dropped: "Dropped and made runnable",
  decoy: "Fake credentials it opened",
  other: "Other file activity",
};

export function fileGroup(f: SandboxFileEvent): FileGroupId {
  if (f.op !== "read" && isPersistencePath(f.path)) return "persistence";
  if (f.decoy) return "decoy";
  if (f.executable || f.op === "exec") return "dropped";
  return "other";
}

export type MergedFile = SandboxFileEvent & { runs: string[] };

/** The same change seen in both runs is one row that says which runs saw it. */
export function mergeFiles(files: SandboxFileEvent[]): MergedFile[] {
  const byKey = new Map<string, MergedFile>();
  for (const f of files) {
    const key = `${f.op}|${f.path}|${f.sha256 ?? ""}`;
    const hit = byKey.get(key);
    if (hit) {
      if (!hit.runs.includes(f.run)) hit.runs.push(f.run);
    } else {
      byKey.set(key, { ...f, runs: [f.run] });
    }
  }
  return [...byKey.values()];
}

export function runsLabel(runs: string[]): string {
  return runs.length > 1 ? "Both runs" : runLabel(runs[0] ?? "");
}

export function groupFiles(sb: SandboxReport): { id: FileGroupId; files: MergedFile[] }[] {
  const order: FileGroupId[] = ["persistence", "dropped", "decoy", "other"];
  const buckets = new Map<FileGroupId, MergedFile[]>();
  for (const f of mergeFiles(sb.files ?? [])) {
    const id = fileGroup(f);
    buckets.set(id, [...(buckets.get(id) ?? []), f]);
  }
  return order.filter((id) => buckets.has(id)).map((id) => ({ id, files: buckets.get(id)! }));
}

const OP_LABEL: Record<string, string> = {
  read: "read",
  write: "wrote",
  delete: "deleted",
  added: "created",
  modified: "changed",
  exec: "ran",
};

export const opLabel = (op: string) => OP_LABEL[op] ?? op;

// --- verdict wording -------------------------------------------------------

export function hasProof(sb?: SandboxReport | null): boolean {
  if (!sb) return false;
  return (sb.canaryHits ?? []).length > 0 || (sb.findings ?? []).some((f) => f.severity === "HIGH");
}

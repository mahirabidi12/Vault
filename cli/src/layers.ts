import type { PackageRef } from "./types.js";

/** The parts of a full report (schema/report.schema.json) that the terminal log reads. All optional: old reports lack some. */
export interface ReportLite {
  findings?: { layer?: string; severity?: string }[];
  intel?: { osv?: { maliciousIds?: string[] }; safedep?: { isMalware?: boolean } };
  metadata?: { installScripts?: Record<string, string>; publishedAt?: string | null };
  codeScan?: { filesScanned?: number };
  sandbox?: { status?: string; skipReason?: string | null; canaryHits?: { sink?: string }[] };
  aiReview?: { verdict?: string; confidence?: string };
}

export type Mark = "ok" | "warn" | "bad" | "off";
export interface LayerLine {
  mark: Mark;
  name: string;
  text: string;
}

const SYMBOL: Record<Mark, string> = { ok: "✓", warn: "!", bad: "✗", off: "-" };

function age(iso: string | null | undefined, now: Date): string | undefined {
  const published = iso ? new Date(iso).getTime() : NaN;
  if (Number.isNaN(published)) return undefined;
  const days = Math.max(0, Math.floor((now.getTime() - published) / 86_400_000));
  if (days < 1) return "published today";
  if (days < 60) return `${days} day${days === 1 ? "" : "s"} old`;
  if (days < 730) return `${Math.floor(days / 30)} months old`;
  return `${Math.floor(days / 365)} years old`;
}

/** One line per check layer, from the data the API already returns. Pure, so it is easy to test. */
export function layerLines(report: ReportLite, now: Date = new Date()): LayerLine[] {
  const findings = report.findings ?? [];
  const count = (layer: string) => findings.filter((f) => f.layer === layer).length;
  const lines: LayerLine[] = [];

  const known = (report.intel?.osv?.maliciousIds?.length ?? 0) > 0 || report.intel?.safedep?.isMalware === true;
  lines.push({ mark: known ? "bad" : "ok", name: "Threat intel", text: known ? "known malware (OSV / SafeDep)" : "no match (OSV, SafeDep)" });

  const scripts = Object.keys(report.metadata?.installScripts ?? {});
  const info = [scripts.length ? `${scripts.join(", ")} script` : "no install scripts", age(report.metadata?.publishedAt, now)].filter(Boolean);
  const metaFlags = count("metadata");
  lines.push({ mark: scripts.length || metaFlags ? "warn" : "ok", name: "Package info", text: info.join(" · ") + (metaFlags ? ` · ${metaFlags} flag${metaFlags === 1 ? "" : "s"}` : "") });

  const codeFindings = count("static");
  const files = report.codeScan?.filesScanned;
  lines.push({
    mark: findings.some((f) => f.layer === "static" && f.severity !== "LOW") ? "warn" : "ok", // LOW-only findings are normal noise
    name: "Static scan",
    text: `${files === undefined ? "code" : `${files} files`}, ${codeFindings} finding${codeFindings === 1 ? "" : "s"}`,
  });

  const sandbox = report.sandbox;
  if (!sandbox || sandbox.status !== "COMPLETE") {
    lines.push({ mark: "off", name: "Sandbox", text: sandbox?.skipReason ? `not run (${sandbox.skipReason})` : "not run" });
  } else if (sandbox.canaryHits?.length) {
    const sink = (sandbox.canaryHits[0].sink ?? "").replace(/^\w+ /, "");
    lines.push({ mark: "bad", name: "Sandbox", text: `sent fake credentials${sink ? ` to ${sink}` : ""}` });
  } else {
    lines.push({ mark: "ok", name: "Sandbox", text: "ran install + load in isolation, no secrets taken" });
  }

  const ai = report.aiReview;
  if (ai?.verdict) {
    const mark: Mark = ai.verdict === "MALICIOUS" ? "bad" : ai.verdict === "SUSPICIOUS" ? "warn" : "ok";
    lines.push({ mark, name: "AI review", text: `${ai.verdict}${ai.confidence ? ` (${ai.confidence.toLowerCase()} confidence)` : ""}` });
  } else {
    lines.push({ mark: "off", name: "AI review", text: "not run" });
  }
  return lines;
}

export function formatLayerLine(line: LayerLine): string {
  return `  ${SYMBOL[line.mark]} ${line.name.padEnd(13)} ${line.text}`;
}

export function refOf(pkg: PackageRef): string {
  return `${pkg.name}@${pkg.version}`;
}

/** "1 package checked · 0 issues · 3.2s" */
export function formatSummary(checked: number, issues: number, seconds: number): string {
  return `${checked} package${checked === 1 ? "" : "s"} checked · ${issues} issue${issues === 1 ? "" : "s"} · ${seconds.toFixed(1)}s`;
}

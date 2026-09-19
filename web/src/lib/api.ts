/**
 * The one data module every page/component calls through (BRIEF.md §6).
 * Today it's backed by fixtures + an in-memory "live scan" simulator so the
 * pending -> scanning -> complete UI can be built and demoed. Swapping to
 * the real API later means rewriting the bodies of these functions only —
 * every caller keeps working.
 *
 * Set NEXT_PUBLIC_API_URL + NEXT_PUBLIC_USE_FIXTURES=false to point at the
 * real backend once it exists; that branch is stubbed below and currently
 * unused since the backend (Step 3) isn't built yet.
 */
import type { PackageRef, Report, VerdictRecord } from "@/lib/types/domain";

import safeExpressRecord from "@/fixtures/safe-express/record.json";
import safeExpressReport from "@/fixtures/safe-express/report.json";
import safeLodashRecord from "@/fixtures/safe-lodash-low-findings/record.json";
import safeLodashReport from "@/fixtures/safe-lodash-low-findings/report.json";
import esbuildRecord from "@/fixtures/ai-cleared-esbuild/record.json";
import esbuildReport from "@/fixtures/ai-cleared-esbuild/report.json";
import maliciousRecord from "@/fixtures/malicious-safedep-test-pkg/record.json";
import maliciousReport from "@/fixtures/malicious-safedep-test-pkg/report.json";
import sbx0Record from "@/fixtures/sandbox-clean/record.json";
import sbx0Report from "@/fixtures/sandbox-clean/report.json";
import sbx1Record from "@/fixtures/sandbox-conditional-ci-gate/record.json";
import sbx1Report from "@/fixtures/sandbox-conditional-ci-gate/report.json";
import sbx2Record from "@/fixtures/sandbox-dropper/record.json";
import sbx2Report from "@/fixtures/sandbox-dropper/report.json";
import sbx3Record from "@/fixtures/sandbox-malicious-exfil/record.json";
import sbx3Report from "@/fixtures/sandbox-malicious-exfil/report.json";
import sbx4Record from "@/fixtures/sandbox-persistence/record.json";
import sbx4Report from "@/fixtures/sandbox-persistence/report.json";
import failedRecordShape from "@/fixtures/failed.record.json";
import skippedRecordShape from "@/fixtures/skipped.record.json";
import { FEED_SEED } from "@/fixtures/feed-seed";
import directorySnapshot from "@/fixtures/directory-snapshot.json";

const USE_FIXTURES = process.env.NEXT_PUBLIC_USE_FIXTURES !== "false";
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "";
const API_KEY = process.env.NEXT_PUBLIC_API_KEY;

// ---------------------------------------------------------------------------
// Fixture registry
// ---------------------------------------------------------------------------

interface Entry {
  record: VerdictRecord;
  report: Report;
}

const FIXTURES: Entry[] = [
  { record: safeExpressRecord as unknown as VerdictRecord, report: safeExpressReport as unknown as Report },
  { record: safeLodashRecord as unknown as VerdictRecord, report: safeLodashReport as unknown as Report },
  { record: esbuildRecord as unknown as VerdictRecord, report: esbuildReport as unknown as Report },
  { record: maliciousRecord as unknown as VerdictRecord, report: maliciousReport as unknown as Report },
  { record: sbx0Record as unknown as VerdictRecord, report: sbx0Report as unknown as Report },
  { record: sbx1Record as unknown as VerdictRecord, report: sbx1Report as unknown as Report },
  { record: sbx2Record as unknown as VerdictRecord, report: sbx2Report as unknown as Report },
  { record: sbx3Record as unknown as VerdictRecord, report: sbx3Report as unknown as Report },
  { record: sbx4Record as unknown as VerdictRecord, report: sbx4Report as unknown as Report },
  ...FEED_SEED,
];

function keyFor(name: string, version?: string | null): string {
  return `${name.toLowerCase()}@${version ?? "*"}`;
}

const BY_NAME_VERSION = new Map<string, Entry>();
const BY_NAME_LATEST = new Map<string, Entry>();
const BY_SCAN_ID = new Map<string, Entry>();
for (const entry of FIXTURES) {
  BY_NAME_VERSION.set(keyFor(entry.record.package.name, entry.record.package.version), entry);
  BY_NAME_LATEST.set(entry.record.package.name.toLowerCase(), entry);
  BY_SCAN_ID.set(entry.record.scanId, entry);
}

// ---------------------------------------------------------------------------
// Live scan simulator
// ---------------------------------------------------------------------------
// Timings for the fake pipeline. Real analyzer runs in 2-7s (PROGRESS.md);
// we mirror that so the progress UI feels real.
export const PENDING_MS = 700;
export const SCANNING_MS = 2600;
export const LIVE_SCAN_TOTAL_MS = PENDING_MS + SCANNING_MS;

type FailureMode = { status: "FAILED" | "SKIPPED"; reason: string };

const FAILURE_TRIGGERS: Record<string, FailureMode> = {
  "tampered-package": {
    status: "FAILED",
    reason: (failedRecordShape as { failureReason: string }).failureReason,
  },
  "huge-package": {
    status: "SKIPPED",
    reason: (skippedRecordShape as { failureReason: string }).failureReason,
  },
};

function classifyDemoVerdict(name: string): {
  verdict: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
  confidence: "HIGH" | "MEDIUM" | "LOW";
  summary: string;
  signals: string[];
} {
  const n = name.toLowerCase();
  if (/(evil|malware|hack|steal)/.test(n)) {
    return {
      verdict: "MALICIOUS",
      confidence: "HIGH",
      summary: "Runs an install script that reads environment variables and sends them over the network.",
      signals: ["Runs a 'postinstall' script during install", "Sends data over the network during install"],
    };
  }
  if (/(sus|backdoor|shady)/.test(n)) {
    return {
      verdict: "SUSPICIOUS",
      confidence: "LOW",
      summary: "Runs system commands during install. Not confirmed malicious.",
      signals: ["Runs system commands (child_process)"],
    };
  }
  return {
    verdict: "SAFE",
    confidence: "MEDIUM",
    summary: "No issues found in threat intelligence, package metadata or code.",
    signals: [],
  };
}

interface LiveScan {
  scanId: string;
  startedAt: number;
  ref: PackageRef;
  failure?: FailureMode;
  finalRecord?: VerdictRecord;
  finalReport?: Report;
}

const liveScans = new Map<string, LiveScan>();

function fakeUlid(): string {
  const chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  let out = "";
  for (let i = 0; i < 26; i++) out += chars[Math.floor(Math.random() * chars.length)];
  return out;
}

function getOrStartLiveScan(ref: PackageRef): LiveScan {
  const k = keyFor(ref.name, ref.version);
  let scan = liveScans.get(k);
  if (!scan) {
    scan = {
      scanId: fakeUlid(),
      startedAt: Date.now(),
      ref,
      failure: FAILURE_TRIGGERS[ref.name.toLowerCase()],
    };
    liveScans.set(k, scan);
  }
  return scan;
}

function materializeLiveScan(scan: LiveScan): VerdictRecord {
  const elapsed = Date.now() - scan.startedAt;
  const requestedAt = new Date(scan.startedAt).toISOString();

  if (elapsed < PENDING_MS) {
    return {
      package: scan.ref,
      status: "PENDING",
      scanId: scan.scanId,
      signals: [],
      requestedAt,
      ranOn: "cloud",
      analyzerVersion: "0.1.0",
      source: "pkgguard",
      aiFailed: false,
    };
  }

  if (elapsed < PENDING_MS + SCANNING_MS) {
    return {
      package: scan.ref,
      status: "SCANNING",
      scanId: scan.scanId,
      signals: [],
      requestedAt,
      ranOn: "cloud",
      analyzerVersion: "0.1.0",
      source: "pkgguard",
      aiFailed: false,
    };
  }

  // Terminal state — compute once, then memoize.
  if (!scan.finalRecord) {
    const analyzedAt = new Date(scan.startedAt + PENDING_MS + SCANNING_MS).toISOString();
    if (scan.failure) {
      scan.finalRecord = {
        package: scan.ref,
        status: scan.failure.status,
        scanId: scan.scanId,
        signals: [],
        requestedAt,
        analyzedAt,
        ranOn: "cloud",
        analyzerVersion: "0.1.0",
        source: "pkgguard",
        aiFailed: false,
        failureReason: scan.failure.reason,
      };
    } else {
      const demo = classifyDemoVerdict(scan.ref.name);
      scan.finalRecord = {
        package: scan.ref,
        status: "COMPLETE",
        scanId: scan.scanId,
        verdict: demo.verdict,
        confidence: demo.confidence,
        decidedBy: "rules",
        summary: demo.summary,
        signals: demo.signals,
        requestedAt,
        analyzedAt,
        ranOn: "cloud",
        analyzerVersion: "0.1.0",
        source: "pkgguard",
        aiFailed: false,
      };
      scan.finalReport = {
        package: scan.ref,
        analyzerVersion: "0.1.0",
        generatedAt: analyzedAt,
        findings:
          demo.verdict === "SAFE"
            ? []
            : [
                {
                  ruleId: demo.verdict === "MALICIOUS" ? "code.exfiltration" : "code.exec",
                  layer: "static",
                  severity: demo.verdict === "MALICIOUS" ? "HIGH" : "MEDIUM",
                  confidence: demo.confidence,
                  title: demo.signals[0] ?? demo.summary,
                  file: "install.js",
                  line: 1,
                  snippet: "// simulated finding for demo purposes",
                  installTime: true,
                  occurrences: 1,
                },
              ],
        intel: { osv: { maliciousIds: [], vulnerabilityIds: [] } },
        metadata: {
          description: "Simulated scan result (this package is not in the fixture set).",
          license: "Unknown",
          publisher: "unknown",
          trustedPublishing: false,
          provenance: false,
          maintainers: [],
          publishedAt: requestedAt,
          previousVersion: null,
          installScripts: {},
          repository: null,
          dependencies: {},
          fileCount: 0,
          unpackedBytes: 0,
        },
        codeScan: {
          filesScanned: 0,
          filesParsed: 0,
          filesWithParseErrors: 0,
          installTimeFiles: [],
          entryFiles: [],
          executables: [],
          skipped: [],
          findingsTruncated: false,
        },
        aiReview: null,
        humanReview: null,
      };
    }
    BY_SCAN_ID.set(scan.scanId, { record: scan.finalRecord, report: scan.finalReport ?? emptyReport(scan.ref) });
  }
  return scan.finalRecord;
}

function emptyReport(ref: PackageRef): Report {
  return {
    package: ref,
    analyzerVersion: "0.1.0",
    generatedAt: new Date().toISOString(),
    findings: [],
    intel: {},
    metadata: {},
    codeScan: {},
    aiReview: null,
    humanReview: null,
  };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Real backend (cloud/api.py, or `pkgguard-dev-api` for local development —
// analyzer/src/pkgguard_analyzer/local_api.py serves the identical contract
// in-memory at http://127.0.0.1:8787). Used when NEXT_PUBLIC_USE_FIXTURES is
// exactly "false"; NEXT_PUBLIC_API_URL must point at that server.
//
//   cd analyzer && uv run pkgguard-dev-api --no-ai
//   # web/.env.local: NEXT_PUBLIC_API_URL=http://127.0.0.1:8787
//   #                 NEXT_PUBLIC_USE_FIXTURES=false
// ---------------------------------------------------------------------------

class ApiClientError extends Error {
  status?: number;
  constructor(message: string, status?: number) {
    super(message);
    this.status = status;
  }
}

// The backend can briefly answer 502/503/504 when its Lambda concurrency is used up by scans. Those clear in
// seconds, so requests are retried a few times before an error reaches the page.
const RETRY_STATUSES = new Set([502, 503, 504]);
const RETRY_DELAYS_MS = [400, 900, 1800];
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/** Every route (cloud/api.py `handler`) returns JSON, {"error": msg} on 4xx/5xx. */
async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  if (!API_URL) {
    throw new ApiClientError(
      "NEXT_PUBLIC_API_URL is not set. Run `uv run pkgguard-dev-api` in analyzer/ and point NEXT_PUBLIC_API_URL at it."
    );
  }
  let res: Response | undefined;
  for (let attempt = 0; attempt <= RETRY_DELAYS_MS.length; attempt++) {
    try {
      res = await fetch(`${API_URL}${path}`, {
        ...init,
        headers: {
          "content-type": "application/json",
          ...(API_KEY ? { "x-api-key": API_KEY } : {}),
          ...init?.headers,
        },
      });
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new ApiClientError(`Could not reach the PkgGuard API at ${API_URL}: ${detail}`);
    }
    if (!RETRY_STATUSES.has(res.status) || attempt === RETRY_DELAYS_MS.length) break;
    await sleep(RETRY_DELAYS_MS[attempt]);
  }
  if (!res) throw new ApiClientError("No response from the PkgGuard API.");
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    if (RETRY_STATUSES.has(res.status)) throw new ApiClientError("PkgGuard is busy right now. Please try again in a few seconds.", res.status);
    throw new ApiClientError(`PkgGuard API returned a non-JSON response (HTTP ${res.status}) for ${path}.`, res.status);
  }
  if (res.status >= 400) {
    const message = (body as { error?: string } | null)?.error ?? (RETRY_STATUSES.has(res.status) ? "PkgGuard is busy right now. Please try again in a few seconds." : `HTTP ${res.status}`);
    throw new ApiClientError(RETRY_STATUSES.has(res.status) ? message : `PkgGuard API error: ${message}`, res.status);
  }
  return body as T;
}

/** Like apiFetch, but a 404 resolves to null instead of throwing (report not ready / scan not found). */
async function apiFetchOrNull<T>(path: string): Promise<T | null> {
  try {
    return await apiFetch<T>(path);
  } catch (error) {
    if (error instanceof ApiClientError && error.status === 404) return null;
    throw error;
  }
}

// ---------------------------------------------------------------------------
// Public API — every page/component calls through these
// ---------------------------------------------------------------------------

export async function getPackage(name: string, version?: string): Promise<VerdictRecord> {
  if (!USE_FIXTURES) {
    const params = new URLSearchParams({ ecosystem: "npm", name });
    if (version) params.set("version", version);
    return apiFetch<VerdictRecord>(`/v1/package?${params.toString()}`);
  }

  await delay(120);
  const exact = version ? BY_NAME_VERSION.get(keyFor(name, version)) : undefined;
  const latest = !version ? BY_NAME_LATEST.get(name.toLowerCase()) : undefined;
  const found = exact ?? latest;
  if (found) return found.record;

  const ref: PackageRef = { ecosystem: "npm", name, version: version ?? "1.0.0" };
  const scan = getOrStartLiveScan(ref);
  return materializeLiveScan(scan);
}

export async function getReport(name: string, version: string): Promise<Report | null> {
  if (!USE_FIXTURES) {
    const params = new URLSearchParams({ ecosystem: "npm", name, version });
    return apiFetchOrNull<Report>(`/v1/report?${params.toString()}`);
  }

  await delay(120);
  const found = BY_NAME_VERSION.get(keyFor(name, version)) ?? BY_NAME_LATEST.get(name.toLowerCase());
  if (found) return found.report;

  const scan = liveScans.get(keyFor(name, version));
  if (scan?.finalReport) return scan.finalReport;
  return null;
}

export async function getScan(scanId: string): Promise<VerdictRecord | null> {
  if (!USE_FIXTURES) {
    return apiFetchOrNull<VerdictRecord>(`/v1/scans/${encodeURIComponent(scanId)}`);
  }

  await delay(80);
  const fromLive = [...liveScans.values()].find((s) => s.scanId === scanId);
  if (fromLive) return materializeLiveScan(fromLive);
  return BY_SCAN_ID.get(scanId)?.record ?? null;
}

export async function getVersions(name: string): Promise<VerdictRecord[]> {
  if (!USE_FIXTURES) {
    const params = new URLSearchParams({ ecosystem: "npm", name });
    const { items } = await apiFetch<{ items: VerdictRecord[] }>(`/v1/package/versions?${params.toString()}`);
    return items;
  }

  await delay(100);
  return FIXTURES.filter((e) => e.record.package.name.toLowerCase() === name.toLowerCase()).map((e) => e.record);
}

export interface Stats {
  totalScanned: number;
  safeCount: number;
  suspiciousCount: number;
  maliciousCount: number;
  avgScanSeconds: number;
}

export async function getStats(): Promise<Stats> {
  if (!USE_FIXTURES) {
    // cloud/api.py's store.stats() shape: {scansCompleted, safe, suspicious, malicious, skipped}.
    // avgScanSeconds isn't tracked server-side; PROGRESS.md's own measured range (~2-7s) stands in.
    const raw = await apiFetch<{ scansCompleted?: number; safe?: number; suspicious?: number; malicious?: number }>(
      "/v1/stats"
    );
    return {
      totalScanned: raw.scansCompleted ?? 0,
      safeCount: raw.safe ?? 0,
      suspiciousCount: raw.suspicious ?? 0,
      maliciousCount: raw.malicious ?? 0,
      avgScanSeconds: 3.4,
    };
  }

  await delay(80);
  const complete = FIXTURES.filter((e) => e.record.status === "COMPLETE");
  const live = [...liveScans.values()]
    .map((s) => s.finalRecord)
    .filter((r): r is VerdictRecord => !!r && r.status === "COMPLETE");
  const all = [...complete.map((e) => e.record), ...live];
  return {
    totalScanned: 48213 + all.length,
    safeCount: all.filter((r) => r.verdict === "SAFE").length + 47960,
    suspiciousCount: all.filter((r) => r.verdict === "SUSPICIOUS").length + 189,
    maliciousCount: all.filter((r) => r.verdict === "MALICIOUS").length + 64,
    avgScanSeconds: 3.4,
  };
}

export async function search(query: string): Promise<VerdictRecord[]> {
  const q = query.trim();
  if (!q) return [];

  if (!USE_FIXTURES) {
    // There's no real search endpoint yet (README §10 lists it as TBD). Reuse
    // "all known versions of this exact name" as the closest honest stand-in —
    // it's a read, so it never kicks off a scan just because someone typed a
    // name. The search page's own "scan it now" button is the deliberate
    // entry point for that.
    return getVersions(q);
  }

  const ql = q.toLowerCase();
  return FIXTURES.filter((e) => e.record.package.name.toLowerCase().includes(ql))
    .map((e) => e.record)
    .sort((a, b) => {
      const an = a.package.name.toLowerCase();
      const bn = b.package.name.toLowerCase();
      if (an === ql) return -1;
      if (bn === ql) return 1;
      return an.localeCompare(bn);
    });
}

// ---------------------------------------------------------------------------
// Package directory: every package PkgGuard has scanned
// ---------------------------------------------------------------------------

export interface PackageListParams {
  q?: string;
  verdict?: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
  /** 1-based page number. */
  page?: number;
  limit?: number;
}

export interface PackageList {
  items: VerdictRecord[];
  total: number;
  page: number;
  pages: number;
  /** True while the server has no /v1/packages route yet: the list comes from a saved snapshot plus recent flagged scans. */
  partial: boolean;
  snapshotAt: string | null;
}

const matchesQuery = (r: VerdictRecord, q: string) => r.package.name.toLowerCase().includes(q.trim().toLowerCase());
const keyOf = (r: VerdictRecord) => `${r.package.name}@${r.package.version}`;

function fromSnapshot(row: (typeof directorySnapshot.rows)[number]): VerdictRecord {
  return {
    package: { ecosystem: "npm", name: row.n, version: row.v },
    status: "COMPLETE",
    verdict: row.d as VerdictRecord["verdict"],
    confidence: row.c as VerdictRecord["confidence"],
    decidedBy: row.b as VerdictRecord["decidedBy"],
    summary: row.s || undefined,
    scanId: "",
    requestedAt: row.t ?? new Date(0).toISOString(),
    analyzedAt: row.t ?? undefined,
    signals: [],
    ranOn: "cloud",
    analyzerVersion: "",
  } as VerdictRecord;
}

/**
 * Newest first, but with every page showing a spread of verdicts (mostly no-issues packages, with suspicious and
 * malicious ones sprinkled in), so the default view isn't a wall of one colour.
 */
function mixed(list: VerdictRecord[]): VerdictRecord[] {
  const queues = {
    SAFE: list.filter((r) => r.verdict === "SAFE"),
    SUSPICIOUS: list.filter((r) => r.verdict === "SUSPICIOUS"),
    MALICIOUS: list.filter((r) => r.verdict === "MALICIOUS"),
  };
  const pattern: (keyof typeof queues)[] = ["SAFE", "MALICIOUS", "SAFE", "SUSPICIOUS", "SAFE", "SAFE", "MALICIOUS", "SAFE", "SUSPICIOUS", "SAFE", "SAFE", "SAFE"];
  const out: VerdictRecord[] = [];
  let i = 0;
  while (out.length < list.length) {
    const q = queues[pattern[i++ % pattern.length]];
    const next = q.shift();
    if (next) out.push(next);
    else if (i > list.length * 4) break;
  }
  for (const q of Object.values(queues)) out.push(...q);
  return out;
}

function paginate(list: VerdictRecord[], page: number, limit: number) {
  const pages = Math.max(1, Math.ceil(list.length / limit));
  const p = Math.min(Math.max(1, page), pages);
  return { items: list.slice((p - 1) * limit, p * limit), total: list.length, page: p, pages };
}

/**
 * GET /v1/packages?q=&verdict=&page=&limit= -> { items, total }, newest first (spec in web/PROGRESS.md).
 * Until that route exists (HTTP 404) the list comes from a saved snapshot of the scan database, refreshed with the
 * live flagged-package feed and an exact-name lookup.
 */
export async function listPackages(params: PackageListParams = {}): Promise<PackageList> {
  const limit = params.limit ?? 12;
  const page = params.page ?? 1;
  const q = params.q?.trim() ?? "";

  if (!USE_FIXTURES) {
    const qs = new URLSearchParams({ limit: String(limit), page: String(page) });
    if (q) qs.set("q", q);
    if (params.verdict) qs.set("verdict", params.verdict);
    try {
      const r = await apiFetch<{ items: VerdictRecord[]; total: number }>(`/v1/packages?${qs.toString()}`);
      return { items: r.items, total: r.total, page, pages: Math.max(1, Math.ceil(r.total / limit)), partial: false, snapshotAt: null };
    } catch (error) {
      if (!(error instanceof ApiClientError) || error.status !== 404) throw error;
    }
  }

  const merged = new Map<string, VerdictRecord>();
  const source = USE_FIXTURES ? FIXTURES.map((e) => e.record) : directorySnapshot.rows.map(fromSnapshot);
  for (const r of source) merged.set(keyOf(r), r);
  if (!USE_FIXTURES) {
    // Fresher, live data wins over the snapshot: recent flagged scans and every scanned version of an exact name.
    const feed = await apiFetch<{ items: VerdictRecord[] }>("/v1/feed").catch(() => ({ items: [] as VerdictRecord[] }));
    for (const r of feed.items) merged.set(keyOf(r), r);
    if (q) for (const r of await getVersions(q).catch(() => [] as VerdictRecord[])) merged.set(keyOf(r), r);
  }
  const list = [...merged.values()]
    .filter((r) => r.status === "COMPLETE" && (!q || matchesQuery(r, q)) && (!params.verdict || r.verdict === params.verdict))
    .sort((a, b) => (b.analyzedAt ?? "").localeCompare(a.analyzedAt ?? ""));
  const ordered = !q && !params.verdict ? mixed(list) : list;
  if (USE_FIXTURES) await delay(120);
  return { ...paginate(ordered, page, limit), partial: !USE_FIXTURES, snapshotAt: USE_FIXTURES ? null : directorySnapshot.generatedAt };
}

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
import failedRecordShape from "@/fixtures/failed.record.json";
import skippedRecordShape from "@/fixtures/skipped.record.json";
import { FEED_SEED } from "@/fixtures/feed-seed";

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

export const MAX_CHECK_PACKAGES = 200; // must match analyzer's cloud/api.py

class ApiClientError extends Error {}

/** Every route (cloud/api.py `handler`) returns JSON, {"error": msg} on 4xx/5xx. */
async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  if (!API_URL) {
    throw new ApiClientError(
      "NEXT_PUBLIC_API_URL is not set. Run `uv run pkgguard-dev-api` in analyzer/ and point NEXT_PUBLIC_API_URL at it."
    );
  }
  let res: Response;
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
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new ApiClientError(`PkgGuard API returned a non-JSON response (HTTP ${res.status}) for ${path}.`);
  }
  if (res.status >= 400) {
    const message = (body as { error?: string } | null)?.error ?? `HTTP ${res.status}`;
    throw new ApiClientError(`PkgGuard API error: ${message}`);
  }
  return body as T;
}

/** Like apiFetch, but a 404 resolves to null instead of throwing (report not ready / scan not found). */
async function apiFetchOrNull<T>(path: string): Promise<T | null> {
  if (!API_URL) return apiFetch<T>(path); // let the missing-URL error surface normally
  const res = await fetch(`${API_URL}${path}`, { headers: API_KEY ? { "x-api-key": API_KEY } : undefined });
  if (res.status === 404) return null;
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    throw new ApiClientError(`PkgGuard API returned a non-JSON response (HTTP ${res.status}) for ${path}.`);
  }
  if (res.status >= 400) {
    const message = (body as { error?: string } | null)?.error ?? `HTTP ${res.status}`;
    throw new ApiClientError(`PkgGuard API error: ${message}`);
  }
  return body as T;
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
  return chunks;
}

function errorRecord(pkg: PackageRef, reason: string): VerdictRecord {
  return {
    package: pkg,
    status: "FAILED",
    scanId: "",
    requestedAt: new Date().toISOString(),
    failureReason: reason,
    signals: [],
    ranOn: "cloud",
    analyzerVersion: "unknown",
  };
}

function packageKey(pkg: PackageRef): string {
  return `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
}

interface CheckResponse {
  results: VerdictRecord[];
  errors: { package: Partial<PackageRef>; error: string }[];
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

export async function checkPackages(list: PackageRef[]): Promise<VerdictRecord[]> {
  if (!USE_FIXTURES) {
    if (list.length === 0) return [];
    const byKey = new Map<string, PackageRef>();
    for (const pkg of list) byKey.set(packageKey(pkg), pkg);
    const unique = [...byKey.values()];

    const results = new Map<string, VerdictRecord>();
    for (const batch of chunk(unique, MAX_CHECK_PACKAGES)) {
      const response = await apiFetch<CheckResponse>("/v1/check", {
        method: "POST",
        body: JSON.stringify({ packages: batch }),
      });
      for (const record of response.results) results.set(packageKey(record.package), record);
      for (const failure of response.errors) {
        const pkg = failure.package as PackageRef;
        results.set(packageKey(pkg), errorRecord(pkg, failure.error));
      }
    }
    return unique.map((pkg) => results.get(packageKey(pkg)) ?? errorRecord(pkg, "No result returned by the API."));
  }

  return Promise.all(list.map((p) => getPackage(p.name, p.version)));
}

export interface FeedItem {
  record: VerdictRecord;
  // The real /v1/feed only returns summaries (VerdictRecord), never the full
  // report — nothing in the UI reads .report today, so this stays nullable
  // rather than firing N extra report fetches just to satisfy a type.
  report: Report | null;
}

export async function getFeed(limit = 20): Promise<FeedItem[]> {
  if (!USE_FIXTURES) {
    const { items } = await apiFetch<{ items: VerdictRecord[] }>(`/v1/feed`);
    return items.slice(0, limit).map((record) => ({ record, report: null }));
  }

  await delay(150);
  const items = FIXTURES.filter(
    (e) => e.record.status === "COMPLETE" && e.record.verdict !== "SAFE"
  );
  const live = [...liveScans.values()]
    .map((s) => BY_SCAN_ID.get(s.scanId))
    .filter((e): e is Entry => !!e && e.record.status === "COMPLETE" && e.record.verdict !== "SAFE");
  return [...items, ...live]
    .sort((a, b) => (b.record.analyzedAt ?? "").localeCompare(a.record.analyzedAt ?? ""))
    .slice(0, limit);
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

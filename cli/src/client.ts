import type { CheckResponse, PackageRef, VerdictRecord } from "./types.js";

export const MAX_CHECK_PACKAGES = 200; // must match analyzer/src/pkgguard_analyzer/cloud/api.py

export interface PkgGuardConfig {
  apiUrl: string;
  webUrl?: string;
  pollIntervalMs: number;
  maxWaitMs: number;
  requestTimeoutMs: number;
}

function positiveInt(raw: string | undefined, fallback: number): number {
  const parsed = raw ? Number(raw) : NaN;
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): PkgGuardConfig {
  return {
    apiUrl: stripTrailingSlash(env.PKGGUARD_API_URL ?? ""),
    webUrl: env.PKGGUARD_WEB_URL ? stripTrailingSlash(env.PKGGUARD_WEB_URL) : undefined,
    pollIntervalMs: positiveInt(env.PKGGUARD_POLL_INTERVAL_MS, 1500),
    maxWaitMs: positiveInt(env.PKGGUARD_MAX_WAIT_MS, 60_000),
    requestTimeoutMs: positiveInt(env.PKGGUARD_REQUEST_TIMEOUT_MS, 10_000),
  };
}

export class PkgGuardError extends Error {}

function isPending(record: VerdictRecord): boolean {
  return record.status === "PENDING" || record.status === "SCANNING";
}

function chunk<T>(items: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < items.length; i += size) chunks.push(items.slice(i, i + size));
  return chunks;
}

/** Talks to the PkgGuard HTTP API (cloud, or `pkgguard-dev-api` for local development). */
export class PkgGuardClient {
  constructor(
    private readonly config: PkgGuardConfig,
    private readonly fetchImpl: typeof fetch = fetch
  ) {}

  /** One lookup by name (+ optional exact version; latest is resolved server-side if omitted). */
  async getPackage(name: string, version?: string): Promise<VerdictRecord> {
    this.requireApiUrl();
    const params = new URLSearchParams({ ecosystem: "npm", name });
    if (version) params.set("version", version);
    return this.requestJson<VerdictRecord>(`/v1/package?${params.toString()}`);
  }

  /** Same as getPackage, but polls until the scan finishes or maxWaitMs runs out. */
  async checkPackage(name: string, version?: string, onTick?: (record: VerdictRecord) => void): Promise<VerdictRecord> {
    const deadline = Date.now() + this.config.maxWaitMs;
    let record = await this.getPackage(name, version);
    onTick?.(record);
    while (isPending(record) && Date.now() < deadline) {
      await sleep(this.config.pollIntervalMs);
      record = await this.getPackage(record.package.name, record.package.version);
      onTick?.(record);
    }
    return record;
  }

  /**
   * Batch check (exact versions only — the API rejects anything else). Chunks at
   * MAX_CHECK_PACKAGES and polls by re-sending the same batch until every package
   * has settled or maxWaitMs runs out; already-complete packages come back instantly,
   * so re-polling the whole batch costs nothing extra for them.
   */
  async checkMany(packages: PackageRef[], onTick?: (records: VerdictRecord[]) => void): Promise<VerdictRecord[]> {
    this.requireApiUrl();
    if (packages.length === 0) return [];

    const byKey = new Map<string, PackageRef>();
    for (const pkg of packages) byKey.set(key(pkg), pkg);
    const unique = [...byKey.values()];

    const results = new Map<string, VerdictRecord>();
    const deadline = Date.now() + this.config.maxWaitMs;
    let pending = unique;

    while (pending.length > 0) {
      for (const batch of chunk(pending, MAX_CHECK_PACKAGES)) {
        const response = await this.requestJson<CheckResponse>("/v1/check", {
          method: "POST",
          body: JSON.stringify({ packages: batch }),
        });
        for (const record of response.results) results.set(key(record.package), record);
        for (const failure of response.errors) {
          const pkg = failure.package as PackageRef;
          results.set(key(pkg), errorRecord(pkg, failure.error));
        }
      }
      onTick?.([...results.values()]);
      pending = unique.filter((pkg) => {
        const record = results.get(key(pkg));
        return record !== undefined && isPending(record);
      });
      if (pending.length === 0 || Date.now() >= deadline) break;
      await sleep(this.config.pollIntervalMs);
    }
    return unique.map((pkg) => results.get(key(pkg)) ?? errorRecord(pkg, "No result returned by the API."));
  }

  /** Best-effort human-readable report link. Matches the website's catch-all route (raw name, `/`-separated). */
  reportUrl(name: string, version: string): string | undefined {
    if (this.config.webUrl) return `${this.config.webUrl}/npm/${name}?version=${encodeURIComponent(version)}`;
    if (this.config.apiUrl) return `${this.config.apiUrl}/v1/report?ecosystem=npm&name=${encodeURIComponent(name)}&version=${encodeURIComponent(version)}`;
    return undefined;
  }

  private requireApiUrl(): void {
    if (!this.config.apiUrl) {
      throw new PkgGuardError(
        "PKGGUARD_API_URL is not set. Point it at the deployed PkgGuard API, or run `uv run pkgguard-dev-api` " +
          "in analyzer/ for local development and set PKGGUARD_API_URL=http://127.0.0.1:8787."
      );
    }
  }

  private async requestJson<T>(path: string, init?: RequestInit): Promise<T> {
    const url = `${this.config.apiUrl}${path}`;
    const response = await this.fetchWithTimeout(url, init);
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new PkgGuardError(`PkgGuard API returned a non-JSON response (HTTP ${response.status}) for ${url}.`);
    }
    if (response.status >= 400) {
      const message = (body as { error?: string } | null)?.error ?? `HTTP ${response.status}`;
      throw new PkgGuardError(`PkgGuard API error: ${message}`);
    }
    return body as T;
  }

  private async fetchWithTimeout(url: string, init?: RequestInit): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    try {
      return await this.fetchImpl(url, {
        ...init,
        signal: controller.signal,
        headers: { "content-type": "application/json", ...init?.headers },
      });
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        throw new PkgGuardError(`PkgGuard API did not respond within ${this.config.requestTimeoutMs}ms (${url}).`);
      }
      const detail = error instanceof Error ? error.message : String(error);
      throw new PkgGuardError(`Could not reach the PkgGuard API at ${this.config.apiUrl}: ${detail}`);
    } finally {
      clearTimeout(timer);
    }
  }
}

function key(pkg: PackageRef): string {
  return `${pkg.ecosystem}:${pkg.name}@${pkg.version}`;
}

function errorRecord(pkg: PackageRef, reason: string): VerdictRecord {
  return {
    package: pkg,
    status: "FAILED",
    scanId: "",
    requestedAt: new Date().toISOString(),
    failureReason: reason,
    signals: [],
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

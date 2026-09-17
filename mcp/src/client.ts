import type { VerdictRecord } from "./types.js";

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
    maxWaitMs: positiveInt(env.PKGGUARD_MAX_WAIT_MS, 45_000),
    requestTimeoutMs: positiveInt(env.PKGGUARD_REQUEST_TIMEOUT_MS, 10_000),
  };
}

export class PkgGuardError extends Error {}

/** Talks to the PkgGuard HTTP API (cloud, or `pkgguard-dev-api` for local development). */
export class PkgGuardClient {
  constructor(
    private readonly config: PkgGuardConfig,
    private readonly fetchImpl: typeof fetch = fetch
  ) {}

  /** One lookup. May come back PENDING/SCANNING if this is the first time this version is checked. */
  async getPackage(name: string, version?: string): Promise<VerdictRecord> {
    if (!this.config.apiUrl) {
      throw new PkgGuardError(
        "PKGGUARD_API_URL is not set. Point it at the deployed PkgGuard API, or run `uv run pkgguard-dev-api` " +
          "in analyzer/ for local development and set PKGGUARD_API_URL=http://127.0.0.1:8787."
      );
    }
    const params = new URLSearchParams({ ecosystem: "npm", name });
    if (version) params.set("version", version);
    const url = `${this.config.apiUrl}/v1/package?${params.toString()}`;

    const response = await this.fetchWithTimeout(url);
    let body: unknown;
    try {
      body = await response.json();
    } catch {
      throw new PkgGuardError(`PkgGuard API returned a non-JSON response (HTTP ${response.status}) for "${name}".`);
    }
    if (response.status >= 400) {
      const message = (body as { error?: string } | null)?.error ?? `HTTP ${response.status}`;
      throw new PkgGuardError(`PkgGuard API error for "${name}": ${message}`);
    }
    return body as VerdictRecord;
  }

  /**
   * Looks up a package and, if the scan just started, polls until it finishes or
   * `maxWaitMs` runs out. Returns the last record seen either way — callers check
   * `status` to tell a finished scan from one that's still running.
   */
  async checkPackage(name: string, version?: string): Promise<VerdictRecord> {
    const deadline = Date.now() + this.config.maxWaitMs;
    let record = await this.getPackage(name, version);
    while ((record.status === "PENDING" || record.status === "SCANNING") && Date.now() < deadline) {
      await sleep(this.config.pollIntervalMs);
      record = await this.getPackage(record.package.name, record.package.version);
    }
    return record;
  }

  /** Best-effort human-readable report link. Matches the website's catch-all route (raw name, `/`-separated). */
  reportUrl(name: string, version: string): string | undefined {
    if (this.config.webUrl) {
      return `${this.config.webUrl}/npm/${name}?version=${encodeURIComponent(version)}`;
    }
    if (this.config.apiUrl) {
      return `${this.config.apiUrl}/v1/report?ecosystem=npm&name=${encodeURIComponent(name)}&version=${encodeURIComponent(version)}`;
    }
    return undefined;
  }

  private async fetchWithTimeout(url: string): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.requestTimeoutMs);
    try {
      return await this.fetchImpl(url, { signal: controller.signal });
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

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

import { describe, expect, it, vi } from "vitest";
import { PkgGuardClient, PkgGuardError, loadConfig } from "../src/client.js";
import type { VerdictRecord } from "../src/types.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function baseRecord(overrides: Partial<VerdictRecord> = {}): VerdictRecord {
  return {
    package: { ecosystem: "npm", name: "example", version: "1.0.0" },
    status: "COMPLETE",
    scanId: "01SCAN000000000000000000",
    requestedAt: "2026-09-17T00:00:00Z",
    signals: [],
    ...overrides,
  };
}

const config = {
  apiUrl: "http://127.0.0.1:8787",
  pollIntervalMs: 5,
  maxWaitMs: 30,
  requestTimeoutMs: 200,
};

describe("loadConfig", () => {
  it("strips trailing slashes and applies defaults", () => {
    const loaded = loadConfig({ PKGGUARD_API_URL: "http://api.example/ ".trim() + "//" } as NodeJS.ProcessEnv);
    expect(loaded.apiUrl).toBe("http://api.example");
    expect(loaded.pollIntervalMs).toBe(1500);
    expect(loaded.maxWaitMs).toBe(45_000);
  });

  it("falls back to defaults for invalid numbers", () => {
    const loaded = loadConfig({ PKGGUARD_POLL_INTERVAL_MS: "not-a-number" } as NodeJS.ProcessEnv);
    expect(loaded.pollIntervalMs).toBe(1500);
  });
});

describe("PkgGuardClient.getPackage", () => {
  it("builds the query string and encodes scoped names", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(200, baseRecord({ package: { ecosystem: "npm", name: "@babel/core", version: "7.24.0" } })));
    const client = new PkgGuardClient(config, fetchImpl);
    await client.getPackage("@babel/core", "7.24.0");
    const [url] = fetchImpl.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:8787/v1/package?ecosystem=npm&name=%40babel%2Fcore&version=7.24.0");
  });

  it("omits the version param when none is given", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(200, baseRecord()));
    const client = new PkgGuardClient(config, fetchImpl);
    await client.getPackage("example");
    const [url] = fetchImpl.mock.calls[0];
    expect(url).toBe("http://127.0.0.1:8787/v1/package?ecosystem=npm&name=example");
  });

  it("throws PkgGuardError with the API's error message on 4xx/5xx", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(404, { error: "unknown package" }));
    const client = new PkgGuardClient(config, fetchImpl);
    await expect(client.getPackage("nope")).rejects.toThrow(/unknown package/);
  });

  it("throws PkgGuardError when PKGGUARD_API_URL isn't set", async () => {
    const client = new PkgGuardClient({ ...config, apiUrl: "" }, vi.fn());
    await expect(client.getPackage("example")).rejects.toThrow(PkgGuardError);
  });

  it("wraps a fetch abort into a clear timeout message", async () => {
    const fetchImpl = vi.fn().mockImplementation((_url: string, options: { signal: AbortSignal }) => {
      return new Promise((_, reject) => {
        options.signal.addEventListener("abort", () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })));
      });
    });
    const client = new PkgGuardClient({ ...config, requestTimeoutMs: 10 }, fetchImpl);
    await expect(client.getPackage("example")).rejects.toThrow(/did not respond within/);
  });
});

describe("PkgGuardClient.checkPackage", () => {
  it("polls while the scan is pending, then returns the completed record", async () => {
    const pending = baseRecord({ status: "PENDING", verdict: undefined });
    const scanning = baseRecord({ status: "SCANNING", verdict: undefined });
    const complete = baseRecord({ verdict: "SAFE", confidence: "HIGH", decidedBy: "rules" });
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(202, pending))
      .mockResolvedValueOnce(jsonResponse(202, scanning))
      .mockResolvedValueOnce(jsonResponse(200, complete));
    const client = new PkgGuardClient(config, fetchImpl);
    const result = await client.checkPackage("example");
    expect(result.status).toBe("COMPLETE");
    expect(result.verdict).toBe("SAFE");
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("gives up after maxWaitMs and returns the last status seen", async () => {
    const scanning = baseRecord({ status: "SCANNING", verdict: undefined });
    const fetchImpl = vi.fn().mockImplementation(async () => jsonResponse(202, scanning));
    const client = new PkgGuardClient({ ...config, maxWaitMs: 12, pollIntervalMs: 5 }, fetchImpl);
    const result = await client.checkPackage("example");
    expect(result.status).toBe("SCANNING");
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(1);
  });
});

describe("PkgGuardClient.reportUrl", () => {
  it("prefers the website URL and keeps scoped names un-encoded in the path", () => {
    const client = new PkgGuardClient({ ...config, webUrl: "https://pkgguard.example" }, vi.fn());
    expect(client.reportUrl("@babel/core", "7.24.0")).toBe("https://pkgguard.example/npm/@babel/core?version=7.24.0");
  });

  it("falls back to the raw API report endpoint when no website URL is set", () => {
    const client = new PkgGuardClient(config, vi.fn());
    expect(client.reportUrl("example", "1.0.0")).toBe("http://127.0.0.1:8787/v1/report?ecosystem=npm&name=example&version=1.0.0");
  });

  it("returns undefined when neither URL is configured", () => {
    const client = new PkgGuardClient({ ...config, apiUrl: "" }, vi.fn());
    expect(client.reportUrl("example", "1.0.0")).toBeUndefined();
  });
});

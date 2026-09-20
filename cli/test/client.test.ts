import { describe, expect, it, vi } from "vitest";
import { PkgGuardClient, PkgGuardError, loadConfig } from "../src/client.js";
import type { PackageRef, VerdictRecord } from "../src/types.js";

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
}

function record(pkg: PackageRef, overrides: Partial<VerdictRecord> = {}): VerdictRecord {
  return {
    package: pkg,
    status: "COMPLETE",
    scanId: `scan-${pkg.name}`,
    requestedAt: "2026-09-17T00:00:00Z",
    signals: [],
    ...overrides,
  };
}

const config = { apiUrl: "http://127.0.0.1:8787", pollIntervalMs: 5, maxWaitMs: 30, requestTimeoutMs: 200 };

describe("loadConfig", () => {
  it("strips trailing slashes and applies defaults", () => {
    const loaded = loadConfig({ PKGGUARD_API_URL: "http://api.example//" } as NodeJS.ProcessEnv);
    expect(loaded.apiUrl).toBe("http://api.example");
    expect(loaded.maxWaitMs).toBe(300_000);
  });
});

describe("PkgGuardClient.getPackage / checkPackage", () => {
  it("encodes scoped names in the query string", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(200, record({ ecosystem: "npm", name: "@babel/core", version: "7.24.0" })));
    const client = new PkgGuardClient(config, fetchImpl);
    await client.getPackage("@babel/core", "7.24.0");
    expect(fetchImpl.mock.calls[0][0]).toBe("http://127.0.0.1:8787/v1/package?ecosystem=npm&name=%40babel%2Fcore&version=7.24.0");
  });

  it("throws PkgGuardError with the API's message on error responses", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(404, { error: "unknown package" }));
    const client = new PkgGuardClient(config, fetchImpl);
    await expect(client.getPackage("nope")).rejects.toThrow(/unknown package/);
  });

  it("polls checkPackage until the scan completes", async () => {
    const pkg: PackageRef = { ecosystem: "npm", name: "example", version: "1.0.0" };
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(202, record(pkg, { status: "PENDING", verdict: undefined })))
      .mockResolvedValueOnce(jsonResponse(200, record(pkg, { verdict: "SAFE", confidence: "HIGH", decidedBy: "rules" })));
    const client = new PkgGuardClient(config, fetchImpl);
    const onTick = vi.fn();
    const result = await client.checkPackage("example", "1.0.0", onTick);
    expect(result.status).toBe("COMPLETE");
    expect(onTick).toHaveBeenCalledTimes(2);
  });
});

describe("PkgGuardClient.checkMany", () => {
  it("returns a record for every requested package, deduped", async () => {
    const a: PackageRef = { ecosystem: "npm", name: "a", version: "1.0.0" };
    const b: PackageRef = { ecosystem: "npm", name: "b", version: "2.0.0" };
    const fetchImpl = vi.fn().mockImplementation(async () => jsonResponse(200, { results: [record(a), record(b)], errors: [] }));
    const client = new PkgGuardClient(config, fetchImpl);
    const results = await client.checkMany([a, b, a]);
    expect(results).toHaveLength(2);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [, init] = fetchImpl.mock.calls[0];
    expect(JSON.parse(init.body).packages).toHaveLength(2);
  });

  it("chunks requests larger than MAX_CHECK_PACKAGES", async () => {
    const packages: PackageRef[] = Array.from({ length: 250 }, (_, i) => ({ ecosystem: "npm" as const, name: `pkg${i}`, version: "1.0.0" }));
    const fetchImpl = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      const body = JSON.parse(init.body as string) as { packages: PackageRef[] };
      return jsonResponse(200, { results: body.packages.map((p) => record(p)), errors: [] });
    });
    const client = new PkgGuardClient(config, fetchImpl);
    const results = await client.checkMany(packages);
    expect(results).toHaveLength(250);
    expect(fetchImpl).toHaveBeenCalledTimes(2); // 200 + 50
  });

  it("polls only the still-pending subset until everything settles", async () => {
    const a: PackageRef = { ecosystem: "npm", name: "a", version: "1.0.0" };
    const b: PackageRef = { ecosystem: "npm", name: "b", version: "1.0.0" };
    let call = 0;
    const fetchImpl = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
      call += 1;
      const body = JSON.parse(init.body as string) as { packages: PackageRef[] };
      const results = body.packages.map((p) =>
        p.name === "b" && call === 1 ? record(p, { status: "SCANNING", verdict: undefined }) : record(p, { verdict: "SAFE", confidence: "HIGH", decidedBy: "rules" })
      );
      return jsonResponse(200, { results, errors: [] });
    });
    const client = new PkgGuardClient(config, fetchImpl);
    const results = await client.checkMany([a, b]);
    expect(results.every((r) => r.status === "COMPLETE")).toBe(true);
    expect(call).toBe(2);
    // second call should only re-check "b"
    const secondBody = JSON.parse((fetchImpl.mock.calls[1][1] as RequestInit).body as string) as { packages: PackageRef[] };
    expect(secondBody.packages).toEqual([b]);
  });

  it("turns per-item API errors into FAILED records instead of throwing", async () => {
    const a: PackageRef = { ecosystem: "npm", name: "a", version: "1.0.0" };
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(200, { results: [], errors: [{ package: a, error: "bad name" }] }));
    const client = new PkgGuardClient(config, fetchImpl);
    const [result] = await client.checkMany([a]);
    expect(result.status).toBe("FAILED");
    expect(result.failureReason).toContain("bad name");
  });

  it("gives up after maxWaitMs and returns whatever status was last seen", async () => {
    const a: PackageRef = { ecosystem: "npm", name: "a", version: "1.0.0" };
    const fetchImpl = vi.fn().mockImplementation(async () => jsonResponse(202, { results: [record(a, { status: "SCANNING", verdict: undefined })], errors: [] }));
    const client = new PkgGuardClient({ ...config, maxWaitMs: 12, pollIntervalMs: 5 }, fetchImpl);
    const [result] = await client.checkMany([a]);
    expect(result.status).toBe("SCANNING");
    expect(fetchImpl.mock.calls.length).toBeGreaterThan(1);
  });
});

describe("PkgGuardClient.reportUrl", () => {
  it("keeps scoped names un-encoded in the path", () => {
    const client = new PkgGuardClient({ ...config, webUrl: "https://pkgguard.example" }, vi.fn());
    expect(client.reportUrl("@babel/core", "7.24.0")).toBe("https://pkgguard.example/npm/@babel/core?version=7.24.0");
  });

  it("throws PkgGuardError when the API URL isn't configured", async () => {
    const client = new PkgGuardClient({ ...config, apiUrl: "" }, vi.fn());
    await expect(client.getPackage("example")).rejects.toThrow(PkgGuardError);
  });
});

describe("PkgGuardClient retries a busy API", () => {
  const pkg: PackageRef = { ecosystem: "npm", name: "express", version: "5.2.1" };
  const slow = { ...config, maxWaitMs: 2000 };

  it("keeps asking after 503 until the API answers", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse(503, { message: "Service Unavailable" }))
      .mockResolvedValueOnce(jsonResponse(503, { message: "Service Unavailable" }))
      .mockResolvedValue(jsonResponse(200, record(pkg)));
    const result = await new PkgGuardClient(slow, fetchImpl).getPackage("express", "5.2.1");
    expect(result.status).toBe("COMPLETE");
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  it("retries a dropped connection", async () => {
    const fetchImpl = vi.fn().mockRejectedValueOnce(new Error("socket hang up")).mockResolvedValue(jsonResponse(200, record(pkg)));
    await expect(new PkgGuardClient(slow, fetchImpl).getPackage("express", "5.2.1")).resolves.toMatchObject({ status: "COMPLETE" });
  });

  it("gives up with a clear message when it stays busy", async () => {
    const fetchImpl = vi.fn().mockImplementation(async () => jsonResponse(503, { message: "Service Unavailable" }));
    await expect(new PkgGuardClient(config, fetchImpl).getPackage("express", "5.2.1")).rejects.toThrow(/busy/);
  });

  it("does not retry real errors like 404", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(404, { error: "unknown package" }));
    await expect(new PkgGuardClient(slow, fetchImpl).getPackage("nope")).rejects.toThrow(/unknown package/);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });
});

import { describe, expect, it } from "vitest";
import { parsePackageLock, EXAMPLE_LOCKFILE } from "./lockfile";

function lockV3(packages: Record<string, { version?: string; link?: boolean }>): string {
  return JSON.stringify({ lockfileVersion: 3, packages });
}

describe("parsePackageLock — v2/v3 (packages map)", () => {
  it("extracts name and version from node_modules paths", () => {
    const result = parsePackageLock(lockV3({ "node_modules/express": { version: "4.18.2" } }));
    expect(result).toEqual([{ ecosystem: "npm", name: "express", version: "4.18.2" }]);
  });

  it("handles scoped package names (which contain a slash)", () => {
    const result = parsePackageLock(lockV3({ "node_modules/@babel/core": { version: "7.24.0" } }));
    expect(result).toEqual([{ ecosystem: "npm", name: "@babel/core", version: "7.24.0" }]);
  });

  it("skips the root project entry (empty key)", () => {
    const result = parsePackageLock(
      lockV3({ "": { version: "1.0.0" }, "node_modules/lodash": { version: "4.18.1" } })
    );
    expect(result).toEqual([{ ecosystem: "npm", name: "lodash", version: "4.18.1" }]);
  });

  it("skips entries with no version (e.g. a workspace root that isn't a real dependency)", () => {
    const result = parsePackageLock(lockV3({ "node_modules/no-version": {} }));
    expect(result).toEqual([]);
  });

  it("skips linked (symlinked workspace) entries", () => {
    const result = parsePackageLock(lockV3({ "node_modules/workspace-pkg": { version: "1.0.0", link: true } }));
    expect(result).toEqual([]);
  });

  it("resolves nested node_modules paths to the innermost package", () => {
    const result = parsePackageLock(
      lockV3({ "node_modules/a/node_modules/lodash": { version: "3.0.0" } })
    );
    expect(result).toEqual([{ ecosystem: "npm", name: "lodash", version: "3.0.0" }]);
  });

  it("de-duplicates the same name@version seen at multiple paths", () => {
    const result = parsePackageLock(
      lockV3({
        "node_modules/lodash": { version: "4.18.1" },
        "node_modules/a/node_modules/lodash": { version: "4.18.1" },
      })
    );
    expect(result).toEqual([{ ecosystem: "npm", name: "lodash", version: "4.18.1" }]);
  });

  it("keeps two different versions of the same name as separate entries", () => {
    const result = parsePackageLock(
      lockV3({
        "node_modules/lodash": { version: "4.18.1" },
        "node_modules/a/node_modules/lodash": { version: "3.0.0" },
      })
    );
    expect(result).toHaveLength(2);
    expect(result.map((r) => r.version).sort()).toEqual(["3.0.0", "4.18.1"]);
  });

  it("sorts the result alphabetically by name", () => {
    const result = parsePackageLock(
      lockV3({
        "node_modules/zod": { version: "1.0.0" },
        "node_modules/express": { version: "4.18.2" },
        "node_modules/@babel/core": { version: "7.24.0" },
      })
    );
    expect(result.map((r) => r.name)).toEqual(["@babel/core", "express", "zod"]);
  });

  it("every entry has ecosystem npm", () => {
    const result = parsePackageLock(lockV3({ "node_modules/express": { version: "4.18.2" } }));
    expect(result.every((r) => r.ecosystem === "npm")).toBe(true);
  });
});

describe("parsePackageLock — v1 (nested dependencies tree)", () => {
  it("reads top-level dependencies", () => {
    const raw = JSON.stringify({ dependencies: { express: { version: "4.18.2" } } });
    expect(parsePackageLock(raw)).toEqual([{ ecosystem: "npm", name: "express", version: "4.18.2" }]);
  });

  it("walks nested dependencies recursively", () => {
    const raw = JSON.stringify({
      dependencies: {
        express: {
          version: "4.18.2",
          dependencies: { "body-parser": { version: "1.20.1" } },
        },
      },
    });
    const result = parsePackageLock(raw);
    expect(result).toEqual([
      { ecosystem: "npm", name: "body-parser", version: "1.20.1" },
      { ecosystem: "npm", name: "express", version: "4.18.2" },
    ]);
  });

  it("skips a dependency entry with no version", () => {
    const raw = JSON.stringify({ dependencies: { "no-version": {} } });
    expect(parsePackageLock(raw)).toEqual([]);
  });
});

describe("parsePackageLock — malformed input", () => {
  it("throws on invalid JSON (caller is expected to catch this)", () => {
    expect(() => parsePackageLock("not json")).toThrow();
  });

  it("returns an empty list for valid JSON with neither packages nor dependencies", () => {
    expect(parsePackageLock(JSON.stringify({ name: "empty-app" }))).toEqual([]);
  });
});

describe("EXAMPLE_LOCKFILE", () => {
  it("is itself valid, parseable lockfile JSON with at least one package", () => {
    const result = parsePackageLock(EXAMPLE_LOCKFILE);
    expect(result.length).toBeGreaterThan(0);
    expect(result.every((r) => r.name && r.version)).toBe(true);
  });
});

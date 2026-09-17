import { describe, expect, it } from "vitest";
import { parseLockfile } from "../src/lockfile.js";

describe("parseLockfile", () => {
  it("reads a v2/v3 lockfile's packages map, skipping the root and links", () => {
    const raw = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "my-app", version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/@babel/core": { version: "7.24.0" },
        "node_modules/foo/node_modules/lodash": { version: "3.10.1" },
        "node_modules/linked-pkg": { version: "1.0.0", link: true },
      },
    });
    const result = parseLockfile(raw);
    expect(result).toContainEqual({ ecosystem: "npm", name: "lodash", version: "4.17.21" });
    expect(result).toContainEqual({ ecosystem: "npm", name: "@babel/core", version: "7.24.0" });
    expect(result).toContainEqual({ ecosystem: "npm", name: "lodash", version: "3.10.1" });
    expect(result.find((p) => p.name === "linked-pkg")).toBeUndefined();
    expect(result).toHaveLength(3);
  });

  it("dedupes identical name+version pairs seen at multiple tree positions", () => {
    const raw = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/lodash": { version: "4.17.21" },
        "node_modules/foo/node_modules/lodash": { version: "4.17.21" },
      },
    });
    expect(parseLockfile(raw)).toHaveLength(1);
  });

  it("falls back to the legacy v1 dependency tree", () => {
    const raw = JSON.stringify({
      lockfileVersion: 1,
      dependencies: {
        lodash: { version: "4.17.21" },
        foo: { version: "1.0.0", dependencies: { bar: { version: "2.0.0" } } },
      },
    });
    const result = parseLockfile(raw);
    expect(result).toContainEqual({ ecosystem: "npm", name: "lodash", version: "4.17.21" });
    expect(result).toContainEqual({ ecosystem: "npm", name: "foo", version: "1.0.0" });
    expect(result).toContainEqual({ ecosystem: "npm", name: "bar", version: "2.0.0" });
  });

  it("returns an empty list for a lockfile with no dependencies", () => {
    expect(parseLockfile(JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }))).toEqual([]);
  });
});

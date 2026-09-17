import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { ResolveError, resolveTree, type Runner } from "../src/resolve-tree.js";

let projectDir: string;

beforeEach(async () => {
  projectDir = await mkdtemp(join(tmpdir(), "pkgguard-project-"));
});

afterEach(async () => {
  await rm(projectDir, { recursive: true, force: true });
});

/** Simulates what `npm install --save-exact <specs>` would do to package.json + package-lock.json. */
function fakeNpm(resolved: Record<string, string>): Runner {
  return async (_command, args, cwd) => {
    const names = args.filter((a) => !a.startsWith("-") && a !== "install");
    const packageJson = JSON.parse(await readFile(join(cwd, "package.json"), "utf8"));
    packageJson.dependencies ??= {};
    for (const name of names) {
      const version = resolved[name];
      if (!version) throw new Error(`fakeNpm: no resolved version configured for "${name}"`);
      packageJson.dependencies[name] = version;
    }
    await writeFile(join(cwd, "package.json"), JSON.stringify(packageJson, null, 2));

    const packages: Record<string, { version: string }> = { "": {} };
    for (const [name, version] of Object.entries(packageJson.dependencies)) {
      packages[`node_modules/${name}`] = { version: version as string };
    }
    await writeFile(join(cwd, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages }));
    return { stdout: "", stderr: "" };
  };
}

describe("resolveTree", () => {
  it("resolves a fresh project (no existing package.json) and returns the exact requested versions", async () => {
    const tree = await resolveTree(projectDir, ["lodash"], fakeNpm({ lodash: "4.17.21" }));
    expect(tree.requested).toEqual([{ ecosystem: "npm", name: "lodash", version: "4.17.21" }]);
    expect(tree.all).toContainEqual({ ecosystem: "npm", name: "lodash", version: "4.17.21" });
    await rm(tree.tempDir, { recursive: true, force: true });
  });

  it("carries an existing package.json's dependencies into the temp dir", async () => {
    await writeFile(join(projectDir, "package.json"), JSON.stringify({ name: "app", version: "1.0.0", dependencies: { express: "4.18.2" } }));
    const tree = await resolveTree(projectDir, ["lodash"], fakeNpm({ express: "4.18.2", lodash: "4.17.21" }));
    const packageJson = JSON.parse(await readFile(tree.tempPackageJsonPath, "utf8"));
    expect(packageJson.dependencies.express).toBe("4.18.2");
    await rm(tree.tempDir, { recursive: true, force: true });
  });

  it("cleans up the temp dir and raises ResolveError when npm fails", async () => {
    const failingRunner: Runner = async () => {
      throw new Error("network unreachable");
    };
    await expect(resolveTree(projectDir, ["lodash"], failingRunner)).rejects.toThrow(ResolveError);
  });

  it("raises ResolveError when a requested package never made it into package.json", async () => {
    const noopRunner: Runner = async (_command, _args, cwd) => {
      // npm "succeeds" but never actually adds the package (simulates an npm bug or an odd spec)
      await writeFile(join(cwd, "package-lock.json"), JSON.stringify({ lockfileVersion: 3, packages: { "": {} } }));
      return { stdout: "", stderr: "" };
    };
    await expect(resolveTree(projectDir, ["lodash"], noopRunner)).rejects.toThrow(/did not add "lodash"/);
  });

  it("raises ResolveError when npm never produces a lockfile", async () => {
    const noLockfileRunner: Runner = async () => ({ stdout: "", stderr: "" });
    await expect(resolveTree(projectDir, ["lodash"], noLockfileRunner)).rejects.toThrow(ResolveError);
  });

  it("does not leave a temp dir behind after a failed resolve", async () => {
    let capturedCwd = "";
    const failingRunner: Runner = async (_command, _args, cwd) => {
      capturedCwd = cwd;
      throw new Error("boom");
    };
    await expect(resolveTree(projectDir, ["lodash"], failingRunner)).rejects.toThrow();
    await expect(stat(capturedCwd)).rejects.toThrow();
  });
});

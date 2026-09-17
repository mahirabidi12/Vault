import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { parseLockfile } from "./lockfile.js";
import { parseSpec } from "./spec.js";
import type { PackageRef } from "./types.js";

const execFileAsync = promisify(execFile);

export type Runner = (command: string, args: string[], cwd: string) => Promise<{ stdout: string; stderr: string }>;

export async function npmRunner(command: string, args: string[], cwd: string): Promise<{ stdout: string; stderr: string }> {
  return execFileAsync(command, args, { cwd, maxBuffer: 64 * 1024 * 1024 });
}

export interface ResolvedTree {
  /** Every package in the resolved lockfile — the requested ones plus their full transitive tree. */
  all: PackageRef[];
  /** Exact, pinned version npm chose for each top-level spec that was asked for (`--save-exact`). */
  requested: PackageRef[];
  tempDir: string;
  tempPackageJsonPath: string;
  tempLockfilePath: string;
}

export class ResolveError extends Error {}

/**
 * Resolves what `npm install <specs>` would add, without installing anything or running any
 * scripts: copies package.json (+ lockfile, if present) into a temp dir, runs
 * `npm install --package-lock-only --ignore-scripts --save-exact`, and reads back the result.
 * README's TOCTOU note: the exact versions found here are what must actually get installed later,
 * not whatever `npm install` would re-resolve on its own a few seconds after this check.
 */
export async function resolveTree(cwd: string, specs: string[], runner: Runner = npmRunner): Promise<ResolvedTree> {
  const tempDir = await mkdtemp(join(tmpdir(), "pkgguard-"));
  const tempPackageJsonPath = join(tempDir, "package.json");
  const tempLockfilePath = join(tempDir, "package-lock.json");

  try {
    await writeFile(tempPackageJsonPath, await readOrCreatePackageJson(cwd));
    await copyIfExists(join(cwd, "package-lock.json"), tempLockfilePath);

    try {
      await runner("npm", ["install", "--package-lock-only", "--ignore-scripts", "--save-exact", ...specs], tempDir);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      throw new ResolveError(`Could not resolve the dependency tree for ${specs.join(", ")}: ${detail}`);
    }

    const [packageJson, lockfileRaw] = await Promise.all([
      readFile(tempPackageJsonPath, "utf8"),
      readFile(tempLockfilePath, "utf8").catch(() => {
        throw new ResolveError("npm did not produce a package-lock.json — nothing to check.");
      }),
    ]);

    const all = parseLockfile(lockfileRaw);
    const requested = requestedVersions(specs, JSON.parse(packageJson) as { dependencies?: Record<string, string> });

    return { all, requested, tempDir, tempPackageJsonPath, tempLockfilePath };
  } catch (error) {
    await rm(tempDir, { recursive: true, force: true });
    throw error;
  }
}

export async function cleanupTree(tree: Pick<ResolvedTree, "tempDir">): Promise<void> {
  await rm(tree.tempDir, { recursive: true, force: true });
}

async function readOrCreatePackageJson(cwd: string): Promise<string> {
  try {
    return await readFile(join(cwd, "package.json"), "utf8");
  } catch {
    return JSON.stringify({ name: "pkgguard-install-check", version: "0.0.0", private: true }, null, 2);
  }
}

async function copyIfExists(from: string, to: string): Promise<void> {
  try {
    await writeFile(to, await readFile(from));
  } catch {
    // no existing lockfile — npm will create one from scratch, which is fine.
  }
}

/** Maps each user-typed spec ("foo", "foo@1.2.3", "@scope/foo") to the exact version npm resolved it to. */
function requestedVersions(specs: string[], packageJson: { dependencies?: Record<string, string> }): PackageRef[] {
  const deps = packageJson.dependencies ?? {};
  return specs.map((spec) => {
    const { name } = parseSpec(spec);
    const version = deps[name];
    if (!version) {
      throw new ResolveError(`npm did not add "${name}" to package.json — is "${spec}" a valid, published npm package?`);
    }
    return { ecosystem: "npm" as const, name, version };
  });
}


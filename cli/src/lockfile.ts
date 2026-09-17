import type { PackageRef } from "./types.js";

interface LockfilePackage {
  version?: string;
  link?: boolean;
}

interface LockfileDependency {
  version?: string;
  dependencies?: Record<string, LockfileDependency>;
}

interface Lockfile {
  lockfileVersion?: number;
  packages?: Record<string, LockfilePackage>;
  dependencies?: Record<string, LockfileDependency>;
}

/**
 * Every resolved package in a package-lock.json, deduped by name+version.
 * Supports npm lockfile v2/v3 (`packages`, keyed by node_modules path) and the
 * legacy v1 shape (`dependencies`, a nested tree) as a fallback.
 */
export function parseLockfile(raw: string): PackageRef[] {
  const data = JSON.parse(raw) as Lockfile;
  const found = new Map<string, PackageRef>();

  if (data.packages) {
    for (const [path, info] of Object.entries(data.packages)) {
      if (path === "" || !info?.version || info.link) continue;
      const name = packageNameFromPath(path);
      if (!name) continue;
      add(found, name, info.version);
    }
  } else if (data.dependencies) {
    collectLegacyTree(data.dependencies, found);
  }
  return [...found.values()];
}

function packageNameFromPath(path: string): string | null {
  const marker = "node_modules/";
  const idx = path.lastIndexOf(marker);
  return idx === -1 ? null : path.slice(idx + marker.length) || null;
}

function collectLegacyTree(deps: Record<string, LockfileDependency>, found: Map<string, PackageRef>): void {
  for (const [name, info] of Object.entries(deps)) {
    if (info.version) add(found, name, info.version);
    if (info.dependencies) collectLegacyTree(info.dependencies, found);
  }
}

function add(found: Map<string, PackageRef>, name: string, version: string): void {
  found.set(`${name}@${version}`, { ecosystem: "npm", name, version });
}

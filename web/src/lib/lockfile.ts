import type { PackageRef } from "@/lib/types/domain";

/**
 * Parses an npm `package-lock.json` (v1, v2 or v3) into a flat, de-duplicated
 * list of {name, version}. Everything happens in the browser — the file
 * never leaves it (BRIEF.md §7, page 4).
 */
export function parsePackageLock(raw: string): PackageRef[] {
  const json = JSON.parse(raw) as {
    packages?: Record<string, { version?: string; name?: string; link?: boolean; dev?: boolean }>;
    dependencies?: Record<string, LockV1Dep>;
  };

  const found = new Map<string, PackageRef>();

  if (json.packages) {
    // v2 / v3: keys are paths like "node_modules/express" or
    // "node_modules/@scope/name" or nested "node_modules/a/node_modules/b".
    for (const [key, value] of Object.entries(json.packages)) {
      if (key === "" || !value?.version || value.link) continue;
      const idx = key.lastIndexOf("node_modules/");
      if (idx === -1) continue;
      const name = key.slice(idx + "node_modules/".length);
      if (!name) continue;
      found.set(`${name}@${value.version}`, { ecosystem: "npm", name, version: value.version });
    }
  } else if (json.dependencies) {
    // v1: nested tree, each node keyed by package name at that level.
    walkV1(json.dependencies, found);
  }

  return [...found.values()].sort((a, b) => a.name.localeCompare(b.name));
}

interface LockV1Dep {
  version?: string;
  dependencies?: Record<string, LockV1Dep>;
}

function walkV1(deps: Record<string, LockV1Dep>, found: Map<string, PackageRef>) {
  for (const [name, dep] of Object.entries(deps)) {
    if (dep.version) {
      found.set(`${name}@${dep.version}`, { ecosystem: "npm", name, version: dep.version });
    }
    if (dep.dependencies) walkV1(dep.dependencies, found);
  }
}

export const EXAMPLE_LOCKFILE = JSON.stringify(
  {
    name: "example-app",
    lockfileVersion: 3,
    packages: {
      "": { name: "example-app", version: "1.0.0" },
      "node_modules/express": { version: "4.18.2" },
      "node_modules/lodash": { version: "4.18.1" },
      "node_modules/esbuild": { version: "0.28.2" },
      "node_modules/safedep-test-pkg": { version: "0.1.3" },
      "node_modules/chalk": { version: "6.0.0" },
      "node_modules/picocolors": { version: "1.1.1" },
      "node_modules/zod": { version: "4.6.5" },
    },
  },
  null,
  2
);

import { copyFile } from "node:fs/promises";
import { join } from "node:path";

import { PkgGuardClient, PkgGuardError, loadConfig } from "../client.js";
import { decideOne, exitCode, summarize } from "../decide.js";
import { refOf } from "../layers.js";
import { printResults } from "../report-log.js";
import { confirm } from "../prompt.js";
import { ResolveError, cleanupTree, npmRunner, resolveTree } from "../resolve-tree.js";
import { Spinner } from "../spinner.js";
import type { VerdictRecord } from "../types.js";

export interface InstallOptions {
  cwd: string;
  yes?: boolean;
  json?: boolean;
  /** Check every transitive dependency too, not only the packages that were named. */
  deep?: boolean;
  quiet?: boolean;
}

export async function runInstall(specs: string[], options: InstallOptions): Promise<number> {
  const config = loadConfig();
  // A full-tree check may have to scan many new packages, which takes minutes. Explicit PKGGUARD_MAX_WAIT_MS still wins.
  if (options.deep && !process.env.PKGGUARD_MAX_WAIT_MS) config.maxWaitMs = Math.max(config.maxWaitMs, 600_000);
  const client = new PkgGuardClient(config);
  const started = Date.now();
  const spinner = new Spinner();
  spinner.start(`Resolving ${specs.join(", ")}...`);

  let tree;
  try {
    tree = await resolveTree(options.cwd, specs);
  } catch (error) {
    spinner.stop();
    console.error(error instanceof ResolveError ? error.message : String(error));
    return exitCode("wait");
  }

  const toCheck = options.deep ? tree.all : tree.requested;
  spinner.update(`Checking ${toCheck.length} package(s) with PkgGuard...`);
  let records: VerdictRecord[];
  let fresh = false;
  try {
    records = await client.checkMany(toCheck, (partial) => {
      if (partial.some((r) => r.status === "PENDING" || r.status === "SCANNING")) fresh = true;
      const done = partial.filter((r) => r.status !== "PENDING" && r.status !== "SCANNING").length;
      spinner.update(`Checking ${toCheck.length} package(s) with PkgGuard... (${done}/${toCheck.length})`);
    });
  } catch (error) {
    spinner.stop();
    await cleanupTree(tree);
    console.error(error instanceof PkgGuardError ? error.message : String(error));
    return exitCode("wait");
  }
  spinner.stop();

  const decisions = records.map(decideOne);
  if (!options.quiet && !options.json) console.log(`→ Resolved ${specs.join(", ")} → ${tree.requested.map(refOf).join(", ")}`);
  await printResults(client, decisions, { quiet: options.quiet, json: options.json, elapsedSeconds: (Date.now() - started) / 1000, fresh });
  if (options.json) console.log(JSON.stringify(decisions, null, 2));

  const overall = summarize(decisions);

  if (overall === "block") {
    console.error("\n🛑 Blocked: at least one package is MALICIOUS. Nothing was installed.");
    await cleanupTree(tree);
    return exitCode("block");
  }
  if (overall === "wait") {
    console.error("\n⏳ PkgGuard couldn't finish scanning in time. Nothing was installed — try again shortly.");
    await cleanupTree(tree);
    return exitCode("wait");
  }
  if (overall === "warn" && !options.yes) {
    const proceed = await confirm("\n⚠️  Some packages need a closer look (see above). Install anyway?");
    if (!proceed) {
      console.error("Install cancelled.");
      await cleanupTree(tree);
      return exitCode("warn");
    }
  }

  const skipped = tree.all.length - toCheck.length;
  if (skipped > 0) console.log(`\nChecked ${toCheck.length} package(s). ${skipped} dependencies were not checked; add --deep to check them too.`);

  const pinned = tree.requested.map((r) => `${r.name}@${r.version}`).join(", ");
  console.log(`\nInstalling ${pinned} (exact, checked versions)...`);
  try {
    await copyFile(tree.tempPackageJsonPath, join(options.cwd, "package.json"));
    await copyFile(tree.tempLockfilePath, join(options.cwd, "package-lock.json"));
    await npmRunner("npm", ["install"], options.cwd);
  } finally {
    await cleanupTree(tree);
  }
  console.log("✅ Installed.");
  return 0;
}

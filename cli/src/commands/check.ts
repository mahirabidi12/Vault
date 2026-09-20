import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { PkgGuardClient, PkgGuardError, loadConfig } from "../client.js";
import { decideOne, exitCode, formatDetail, summarize } from "../decide.js";
import { printResults } from "../report-log.js";
import { parseLockfile } from "../lockfile.js";
import { parseSpec } from "../spec.js";
import { Spinner } from "../spinner.js";
import type { VerdictRecord } from "../types.js";

export interface CheckOptions {
  cwd: string;
  json?: boolean;
  quiet?: boolean;
}

export async function runCheck(spec: string | undefined, options: CheckOptions): Promise<number> {
  const client = new PkgGuardClient(loadConfig());
  return spec ? checkOne(client, spec, options) : checkLockfile(client, options);
}

async function checkOne(client: PkgGuardClient, spec: string, options: CheckOptions): Promise<number> {
  const { name, version } = parseSpec(spec);
  const spinner = new Spinner();
  const started = Date.now();
  spinner.start(`Checking ${spec}...`);

  let record: VerdictRecord;
  let fresh = false;
  try {
    record = await client.checkPackage(name, version, (r) => {
      if (r.status === "PENDING" || r.status === "SCANNING") fresh = true;
      spinner.update(`Checking ${spec}... (${r.status === "PENDING" || r.status === "SCANNING" ? "new scan, usually 1-2 minutes" : r.status.toLowerCase()})`);
    });
  } catch (error) {
    spinner.stop();
    console.error(error instanceof PkgGuardError ? error.message : String(error));
    return exitCode("wait");
  }
  spinner.stop();

  const decision = decideOne(record);
  const reportUrl = client.reportUrl(record.package.name, record.package.version);
  if (options.json) {
    console.log(JSON.stringify({ ...decision, reportUrl }, null, 2));
  } else {
    await printResults(client, [decision], { quiet: options.quiet, elapsedSeconds: (Date.now() - started) / 1000, fresh });
  }
  return exitCode(decision.recommendation);
}

async function checkLockfile(client: PkgGuardClient, options: CheckOptions): Promise<number> {
  const lockfilePath = join(options.cwd, "package-lock.json");
  let raw: string;
  try {
    raw = await readFile(lockfilePath, "utf8");
  } catch {
    console.error(
      `No package-lock.json in ${options.cwd}. Run \`pkgguard check <package>\` to check one package, ` +
        "or run this inside a project that has a lockfile."
    );
    return exitCode("wait");
  }

  const packages = parseLockfile(raw);
  if (packages.length === 0) {
    console.log("No packages found in package-lock.json.");
    return 0;
  }

  console.log(`Checking ${packages.length} package${packages.length === 1 ? "" : "s"} from package-lock.json...`);
  const spinner = new Spinner();
  spinner.start("Waiting for PkgGuard...");

  let records: VerdictRecord[];
  try {
    records = await client.checkMany(packages, (partial) => {
      const done = partial.filter((r) => r.status !== "PENDING" && r.status !== "SCANNING").length;
      spinner.update(`Waiting for PkgGuard... (${done}/${packages.length})`);
    });
  } catch (error) {
    spinner.stop();
    console.error(error instanceof PkgGuardError ? error.message : String(error));
    return exitCode("wait");
  }
  spinner.stop();

  const decisions = records.map(decideOne);
  const flagged = decisions.filter((d) => d.recommendation !== "allow");
  if (flagged.length === 0) {
    console.log(`✅ All ${packages.length} packages look safe.`);
  } else {
    console.log(`${flagged.length} of ${packages.length} package(s) need attention:\n`);
    for (const decision of flagged) {
      console.log(formatDetail(decision, client.reportUrl(decision.record.package.name, decision.record.package.version)));
    }
  }
  if (options.json) console.log(JSON.stringify(decisions, null, 2));
  return exitCode(summarize(decisions));
}

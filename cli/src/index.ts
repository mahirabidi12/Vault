#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { Command } from "commander";

import { runCheck } from "./commands/check.js";
import { runInstall } from "./commands/install.js";

const PACKAGE_VERSION = "0.1.5";

/** Loads ../.env (next to package.json) into process.env, without overriding real env vars. No .env file is fine. */
function loadDotEnv(): void {
  let text: string;
  try {
    text = readFileSync(new URL("../.env", import.meta.url), "utf8");
  } catch {
    return;
  }
  for (const line of text.split("\n")) {
    const match = /^\s*([\w.-]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match || line.trim().startsWith("#")) continue;
    const [, key, rawValue] = match;
    if (key in process.env) continue;
    process.env[key] = rawValue.replace(/^(['"])(.*)\1$/, "$2");
  }
}

loadDotEnv();

const program = new Command();
program.name("pkgguard").description("Check npm packages for malware and supply-chain risk before you install them.").version(PACKAGE_VERSION);

program
  .command("check")
  .argument("[package]", "package to check, e.g. lodash or lodash@4.17.21. Omit to check every package in package-lock.json.")
  .description("Check one package, or every package in the current project's lockfile.")
  .option("-q, --quiet", "print only the verdict, not the per-check log")
  .option("--json", "print machine-readable JSON instead of a summary")
  .action(async (pkg: string | undefined, opts: { json?: boolean; quiet?: boolean }) => {
    process.exitCode = await runCheck(pkg, { cwd: process.cwd(), json: opts.json, quiet: opts.quiet });
  });

program
  .command("install")
  .argument("<packages...>", "one or more packages to check and install, e.g. lodash or lodash@4.17.21")
  .description("Check the packages you name with PkgGuard, then install them if they're safe. Add --deep to check the whole dependency tree.")
  .option("-y, --yes", "skip the confirmation prompt for suspicious packages (malicious packages are always blocked)")
  .option("--deep", "also check every transitive dependency (slower; scans each one that is not cached yet)")
  .option("-q, --quiet", "print only verdicts, not the per-check log")
  .option("--json", "print machine-readable JSON alongside the summary")
  .action(async (packages: string[], opts: { yes?: boolean; json?: boolean; deep?: boolean; quiet?: boolean }) => {
    process.exitCode = await runInstall(packages, { cwd: process.cwd(), yes: opts.yes, json: opts.json, deep: opts.deep, quiet: opts.quiet });
  });

await program.parseAsync(process.argv);

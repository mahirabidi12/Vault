#!/usr/bin/env node
import { Command } from "commander";

import { runCheck } from "./commands/check.js";
import { runInstall } from "./commands/install.js";

const PACKAGE_VERSION = "0.1.0";

const program = new Command();
program.name("pkgguard").description("Check npm packages for malware and supply-chain risk before you install them.").version(PACKAGE_VERSION);

program
  .command("check")
  .argument("[package]", "package to check, e.g. lodash or lodash@4.17.21. Omit to check every package in package-lock.json.")
  .description("Check one package, or every package in the current project's lockfile.")
  .option("--json", "print machine-readable JSON instead of a summary")
  .action(async (pkg: string | undefined, opts: { json?: boolean }) => {
    process.exitCode = await runCheck(pkg, { cwd: process.cwd(), json: opts.json });
  });

program
  .command("install")
  .argument("<packages...>", "one or more packages to check and install, e.g. lodash or lodash@4.17.21")
  .description("Check packages (and their full dependency tree) with PkgGuard, then install them if they're safe.")
  .option("-y, --yes", "skip the confirmation prompt for suspicious packages (malicious packages are always blocked)")
  .option("--json", "print machine-readable JSON alongside the summary")
  .action(async (packages: string[], opts: { yes?: boolean; json?: boolean }) => {
    process.exitCode = await runInstall(packages, { cwd: process.cwd(), yes: opts.yes, json: opts.json });
  });

await program.parseAsync(process.argv);

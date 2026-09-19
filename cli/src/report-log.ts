import type { PkgGuardClient } from "./client.js";
import { formatDetail, formatLine, type PackageDecision } from "./decide.js";
import { formatLayerLine, formatSummary, layerLines, refOf } from "./layers.js";

const DETAIL_LIMIT = 3; // per-layer lines for at most this many packages; bigger batches only list the ones needing attention

export interface LogOptions {
  quiet?: boolean;
  json?: boolean;
  /** Seconds since the command started, for the summary line. */
  elapsedSeconds: number;
  /** True when at least one package was scanned fresh instead of served from the cache. */
  fresh: boolean;
}

/** Prints what was checked, layer by layer, then a verdict per package and a one-line summary. */
export async function printResults(client: PkgGuardClient, decisions: PackageDecision[], options: LogOptions): Promise<void> {
  const flagged = decisions.filter((d) => d.recommendation !== "allow");
  const detailed = !options.quiet && !options.json && decisions.length <= DETAIL_LIMIT;

  for (const decision of decisions) {
    const pkg = decision.record.package;
    const reportUrl = client.reportUrl(pkg.name, pkg.version);
    if (detailed) {
      console.log(`→ ${refOf(pkg)}: ${options.fresh ? "new scan" : "already scanned, from cache"}`);
      const report = decision.record.status === "COMPLETE" ? await client.getReport(pkg.name, pkg.version) : undefined;
      if (report) for (const line of layerLines(report)) console.log(formatLayerLine(line));
      console.log(decision.recommendation === "allow" ? `${formatLine(decision)}${reportUrl ? `\n   Report: ${reportUrl}` : ""}` : formatDetail(decision, reportUrl));
    } else if (decision.recommendation !== "allow") {
      console.log(formatDetail(decision, reportUrl));
    }
  }
  if (!options.json) console.log(`→ ${formatSummary(decisions.length, flagged.length, options.elapsedSeconds)}`);
}

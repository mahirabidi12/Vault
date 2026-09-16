import { CodeEvidence } from "@/components/code-evidence";
import { SeverityBadge, InstallTimeBadge, OccurrencesBadge } from "@/components/verdict-ui";
import type { Finding } from "@/lib/types/domain";

export async function FindingCard({ finding }: { finding: Finding }) {
  return (
    <div className="flex flex-col gap-2.5 rounded-xl border border-border bg-card/60 p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={finding.severity} />
          {finding.installTime && <InstallTimeBadge />}
          {finding.occurrences && <OccurrencesBadge count={finding.occurrences} />}
        </div>
        <span className="font-mono text-[11px] text-muted-foreground/70">{finding.ruleId}</span>
      </div>
      <p className="text-sm font-medium text-foreground">{finding.title}</p>
      {finding.snippet && (
        <CodeEvidence file={finding.file} line={finding.line} snippet={finding.snippet} />
      )}
    </div>
  );
}

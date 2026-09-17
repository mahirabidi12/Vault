import { CodeEvidence, type EvidenceTone } from "@/components/code-evidence";
import { SeverityBadge, InstallTimeBadge, OccurrencesBadge } from "@/components/verdict-ui";
import { cn } from "@/lib/utils";
import type { Finding } from "@/lib/types/domain";
import { ShieldAlert, TriangleAlert, Info, CornerDownRight } from "lucide-react";

const TONE_BY_SEVERITY: Record<Finding["severity"], EvidenceTone> = {
  HIGH: "threat",
  MEDIUM: "warn",
  LOW: "neutral",
};

const KICKER: Record<Finding["severity"], { label: string; icon: typeof ShieldAlert }> = {
  HIGH: { label: "Threat detected", icon: ShieldAlert },
  MEDIUM: { label: "Warning", icon: TriangleAlert },
  LOW: { label: "Note", icon: Info },
};

/**
 * A HIGH-severity finding renders as a "special box": a hard colored left
 * edge, a breathing glow, an uppercase threat kicker, a `→` pointer on the
 * flagged line, and a connected annotation explaining why it matters. LOW
 * findings stay deliberately calm — same shape, no color, no glow — so
 * severity reads instantly without needing to parse the badge text.
 */
export async function FindingCard({ finding }: { finding: Finding }) {
  const tone = TONE_BY_SEVERITY[finding.severity];
  const { label: kickerLabel, icon: KickerIcon } = KICKER[finding.severity];

  return (
    <div
      className={cn(
        "relative flex flex-col gap-3 overflow-hidden rounded-lg border pl-4 pr-4 py-4",
        tone === "threat" && "border-malicious/30 bg-malicious-bg/20 threat-box",
        tone === "warn" && "border-suspicious/25 bg-suspicious-bg/15",
        tone === "neutral" && "border-border bg-card/60"
      )}
    >
      <span
        className={cn(
          "absolute inset-y-0 left-0 w-[3px]",
          tone === "threat" && "bg-malicious",
          tone === "warn" && "bg-suspicious",
          tone === "neutral" && "bg-border"
        )}
      />

      <div className="flex flex-wrap items-center justify-between gap-2">
        <span
          className={cn(
            "kicker inline-flex items-center gap-1.5",
            tone === "threat" && "text-malicious",
            tone === "warn" && "text-suspicious",
            tone === "neutral" && "text-muted-foreground"
          )}
        >
          <KickerIcon className="size-3.5" />
          {kickerLabel} · <SeverityBadge severity={finding.severity} className="border-0 bg-transparent p-0 text-inherit" />
        </span>
        <span className="font-mono text-[10.5px] text-muted-foreground/60">{finding.ruleId}</span>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        {finding.installTime && <InstallTimeBadge />}
        {finding.occurrences && <OccurrencesBadge count={finding.occurrences} />}
      </div>

      <p className="text-sm font-medium text-foreground">{finding.title}</p>

      {finding.snippet && (
        <div className="flex flex-col gap-2">
          <CodeEvidence file={finding.file} line={finding.line} snippet={finding.snippet} tone={tone} />
          {tone !== "neutral" && (
            <div
              className={cn(
                "flex items-start gap-2 rounded-md px-3 py-2 font-mono text-[11.5px] leading-relaxed",
                tone === "threat" ? "bg-malicious-bg/40 text-malicious" : "bg-suspicious-bg/40 text-suspicious"
              )}
            >
              <CornerDownRight className="mt-0.5 size-3.5 shrink-0" />
              <span className="text-foreground/80">
                Flagged because it {finding.title.charAt(0).toLowerCase() + finding.title.slice(1)}
                {finding.installTime ? " — and this runs automatically on npm install." : "."}
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

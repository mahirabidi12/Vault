import { VerdictBadge, ConfidencePill, DecidedByPill, OsvImportBadge } from "@/components/verdict-ui";
import { CopyButton } from "@/components/copy-button";
import { formatDateTime, formatRelativeTime, truncateMiddle } from "@/lib/format";
import { verdictStyle } from "@/lib/verdict";
import type { VerdictRecord } from "@/lib/types/domain";
import { Package, ShieldBan, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

export function VerdictHero({ record }: { record: VerdictRecord }) {
  const style = verdictStyle(record.verdict);
  const malicious = record.verdict === "MALICIOUS";
  const safe = record.verdict === "SAFE";

  return (
    <section
      className={cn(
        "relative overflow-hidden rounded-lg border p-6 sm:p-8",
        malicious ? "border-malicious/40 threat-box" : "border-border"
      )}
      style={{
        background: `linear-gradient(135deg, color-mix(in oklch, var(--${style.colorVar}), transparent ${malicious ? 88 : 94}%), var(--card) 55%)`,
      }}
    >
      {malicious && (
        <div
          aria-hidden="true"
          className="absolute inset-x-0 top-0 h-1.5"
          style={{
            backgroundImage:
              "repeating-linear-gradient(-45deg, var(--malicious), var(--malicious) 10px, color-mix(in oklch, var(--malicious), black 30%) 10px, color-mix(in oklch, var(--malicious), black 30%) 20px)",
          }}
        />
      )}
      {safe && (
        <ShieldCheck
          aria-hidden="true"
          className="pointer-events-none absolute -right-6 -top-6 size-32 text-safe/[0.07] sm:size-40"
          strokeWidth={1}
        />
      )}

      <div className="flex flex-col gap-6 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex min-w-0 flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <Package className="size-4" />
            <span className="font-mono">npm</span>
            <span>·</span>
            {record.source === "osv-import" && <OsvImportBadge />}
          </div>
          <h1 className="flex flex-wrap items-baseline gap-2 font-display text-2xl font-semibold tracking-tight sm:text-3xl">
            <span className="truncate">{record.package.name}</span>
            <span className="font-mono text-lg font-normal text-muted-foreground">
              @{record.package.version}
            </span>
          </h1>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <VerdictBadge verdict={record.verdict} size="lg" />
            {malicious && (
              <span className="relative flex size-2.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-malicious opacity-75" />
                <span className="relative inline-flex size-2.5 rounded-full bg-malicious" />
              </span>
            )}
            <ConfidencePill confidence={record.confidence} />
            <DecidedByPill decidedBy={record.decidedBy} />
          </div>

          {record.summary && (
            <p className="max-w-2xl text-balance text-sm text-foreground/90 sm:text-base">
              {record.summary}
            </p>
          )}
          <p className="text-xs text-muted-foreground">{style.description}</p>

          {malicious && (
            <p className="kicker mt-1 inline-flex w-fit items-center gap-1.5 rounded-md bg-malicious px-2.5 py-1.5 text-malicious-foreground">
              <ShieldBan className="size-3.5" />
              Do not install this package
            </p>
          )}
        </div>

        <div className="flex shrink-0 flex-col gap-2 rounded-lg border border-border/70 bg-background/60 p-4 text-xs text-muted-foreground backdrop-blur-sm sm:min-w-[220px]">
          <MetaRow label="Analyzed" value={record.analyzedAt ? formatRelativeTime(record.analyzedAt) : "—"} title={formatDateTime(record.analyzedAt)} />
          <MetaRow label="Published" value={record.publishedAt ? formatRelativeTime(record.publishedAt) : "—"} title={formatDateTime(record.publishedAt)} />
          <MetaRow label="Ran on" value={record.ranOn === "cloud" ? "AWS cloud" : "Local"} />
          {record.sha256 && (
            <div className="flex items-center justify-between gap-2 border-t border-border/60 pt-2">
              <span className="font-medium text-foreground/80">SHA-256</span>
              <CopyButton value={record.sha256} label={truncateMiddle(record.sha256)} className="h-auto px-0 py-0 text-muted-foreground hover:bg-transparent hover:text-foreground" />
            </div>
          )}
        </div>
      </div>
    </section>
  );
}

function MetaRow({ label, value, title }: { label: string; value: string; title?: string }) {
  return (
    <div className="flex items-center justify-between gap-3" title={title}>
      <span className="font-medium text-foreground/80">{label}</span>
      <span>{value}</span>
    </div>
  );
}

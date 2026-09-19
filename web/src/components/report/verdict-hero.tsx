import { VerdictBadge, ConfidencePill, DecidedByPill, OsvImportBadge } from "@/components/verdict-ui";
import { CopyButton } from "@/components/copy-button";
import { formatDateTime, formatRelativeTime, truncateMiddle } from "@/lib/format";
import { verdictStyle } from "@/lib/verdict";
import type { VerdictRecord } from "@/lib/types/domain";
import { Box, FlaskConical, Package, ShieldBan } from "lucide-react";
import { cn } from "@/lib/utils";

const CONFIDENCE_PCT: Record<string, number> = { HIGH: 0.94, MEDIUM: 0.66, LOW: 0.38 };
const RING_R = 54;
const RING_LEN = 2 * Math.PI * RING_R;

export function VerdictHero({ record, evaluationSample = false }: { record: VerdictRecord; evaluationSample?: boolean }) {
  const style = verdictStyle(record.verdict);
  const Icon = style.icon;
  const malicious = record.verdict === "MALICIOUS";
  const color = `var(--${style.colorVar})`;
  const pct = CONFIDENCE_PCT[record.confidence ?? ""] ?? 0.5;

  return (
    <section
      className={cn(
        "relative isolate overflow-hidden rounded-3xl border p-6 sm:p-9",
        malicious ? "border-malicious/40 threat-box" : "border-white/10"
      )}
      style={{ background: "linear-gradient(180deg, rgba(255,255,255,0.035), rgba(255,255,255,0.01))" }}
    >
      {/* living backdrop tinted by the verdict */}
      <div aria-hidden className="pointer-events-none absolute inset-0 -z-10 overflow-hidden">
        <div
          className="blob-drift absolute -left-[10%] -top-[40%] size-[70%] rounded-full blur-3xl"
          style={{ background: `color-mix(in oklch, ${color}, transparent 72%)` }}
        />
        <div
          className="blob-drift absolute -bottom-[50%] right-[-5%] size-[60%] rounded-full blur-3xl [animation-delay:-6s]"
          style={{ background: `color-mix(in oklch, ${color}, transparent 82%)` }}
        />
        <div className="bg-grid absolute inset-0 opacity-50 [mask-image:radial-gradient(ellipse_80%_80%_at_30%_30%,black,transparent)]" />
        <div className="sweep-x absolute inset-y-0 left-0 w-1/4 bg-gradient-to-r from-transparent via-white/10 to-transparent" />
      </div>

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

      <div className="grid gap-8 lg:grid-cols-[1fr_auto] lg:items-center">
        <div className="flex min-w-0 flex-col gap-4">
          <div className="rise-in flex flex-wrap items-center gap-2 text-sm text-muted-foreground">
            <span className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-xs">
              <Package className="size-3.5" />
              npm
            </span>
            {record.source === "osv-import" && <OsvImportBadge />}
            {evaluationSample && (
              <span
                title="The registry data for this package was synthetic and threat-intel lookups were switched off, so we measure our own layers."
                className="inline-flex items-center gap-1.5 rounded-full border border-brand/40 bg-brand/10 px-2.5 py-1 text-xs font-medium text-brand"
              >
                <FlaskConical className="size-3.5" />
                Evaluation sample
              </span>
            )}
            <span className="inline-flex items-center gap-1.5 text-xs">
              <span className="relative flex size-2">
                <span className="ping-ring absolute inline-flex size-full rounded-full" style={{ background: color }} />
                <span className="relative inline-flex size-2 rounded-full" style={{ background: color }} />
              </span>
              Scanned {record.analyzedAt ? formatRelativeTime(record.analyzedAt) : "just now"}
            </span>
          </div>

          <h1 className="rise-in flex flex-wrap items-baseline gap-x-3 gap-y-1 font-display font-semibold tracking-[-0.04em] [animation-delay:80ms]">
            <span className="break-all text-[clamp(2.2rem,6vw,4.2rem)] leading-[1.02]">{record.package.name}</span>
            <span className="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-base font-normal tracking-normal text-muted-foreground sm:text-lg">
              v{record.package.version}
            </span>
          </h1>

          <div className="rise-in flex flex-wrap items-center gap-2 pt-1 [animation-delay:160ms]">
            <VerdictBadge verdict={record.verdict} size="lg" />
            <ConfidencePill confidence={record.confidence} />
            {record.decidedBy === "sandbox" ? (
              <a
                href="#dynamic-analysis"
                className="inline-flex items-center gap-1.5 rounded-full border border-malicious/50 bg-malicious/10 px-3 py-1.5 text-sm font-semibold text-malicious transition-colors hover:bg-malicious/20"
              >
                <Box className="size-4" />
                Confirmed by sandbox run
              </a>
            ) : (
              <DecidedByPill decidedBy={record.decidedBy} />
            )}
          </div>

          {record.summary && (
            <p className="rise-in max-w-2xl text-balance text-base leading-relaxed text-foreground/90 [animation-delay:240ms] sm:text-lg">
              {record.summary}
            </p>
          )}
          <p className="rise-in text-xs text-muted-foreground [animation-delay:300ms]">{style.description}</p>

          {malicious && (
            <p className="kicker rise-in mt-1 inline-flex w-fit items-center gap-1.5 rounded-md bg-malicious px-2.5 py-1.5 text-malicious-foreground [animation-delay:360ms]">
              <ShieldBan className="size-3.5" />
              Do not install this package
            </p>
          )}
        </div>

        {/* verdict gauge */}
        <div className="rise-in flex flex-col items-center gap-4 [animation-delay:200ms]">
          <div className="relative flex size-44 items-center justify-center">
            <span
              aria-hidden
              className="ping-ring absolute size-28 rounded-full border"
              style={{ borderColor: `color-mix(in oklch, ${color}, transparent 50%)` }}
            />
            <svg viewBox="0 0 128 128" className="absolute inset-0 size-full -rotate-90" aria-hidden>
              <circle cx="64" cy="64" r={RING_R} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="6" />
              <circle
                cx="64"
                cy="64"
                r={RING_R}
                fill="none"
                stroke={color}
                strokeWidth="6"
                strokeLinecap="round"
                strokeDasharray={RING_LEN}
                className="ring-fill"
                style={
                  {
                    "--ring-len": RING_LEN,
                    "--ring-to": RING_LEN * (1 - pct),
                    filter: `drop-shadow(0 0 8px ${color})`,
                  } as React.CSSProperties
                }
              />
            </svg>
            <div className="relative flex flex-col items-center gap-1">
              <Icon className="size-11" style={{ color }} strokeWidth={1.6} />
              <span className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                {record.confidence ? `${record.confidence.toLowerCase()} confidence` : "verdict"}
              </span>
            </div>
          </div>

          <div className="flex w-full min-w-[230px] flex-col gap-2 rounded-2xl border border-white/10 bg-black/40 p-4 text-xs text-muted-foreground backdrop-blur-sm">
            <MetaRow label="Analyzed" value={record.analyzedAt ? formatRelativeTime(record.analyzedAt) : "—"} title={formatDateTime(record.analyzedAt)} />
            <MetaRow label="Published" value={record.publishedAt ? formatRelativeTime(record.publishedAt) : "—"} title={formatDateTime(record.publishedAt)} />
            <MetaRow label="Ran on" value={record.ranOn === "cloud" ? "AWS cloud" : "Local"} />
            {record.sha256 && (
              <div className="flex items-center justify-between gap-2 border-t border-white/10 pt-2">
                <span className="font-medium text-foreground/80">SHA-256</span>
                <CopyButton value={record.sha256} label={truncateMiddle(record.sha256)} className="h-auto px-0 py-0 text-muted-foreground hover:bg-transparent hover:text-foreground" />
              </div>
            )}
          </div>
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

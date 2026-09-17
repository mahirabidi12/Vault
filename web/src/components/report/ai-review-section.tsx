import { ShieldAlert, Sparkles, FileText, Clock, Wrench } from "lucide-react";
import { VerdictBadge, ConfidencePill } from "@/components/verdict-ui";
import { verdictStyle } from "@/lib/verdict";
import type { AIReview, Verdict } from "@/lib/types/domain";

/**
 * Renders defensively: the analyzer's AI step (Step 5) is new, so every
 * field here is treated as possibly absent even where the schema now marks
 * it required, per BRIEF.md §5.3.
 *
 * `finalVerdict` is the record's actual verdict (the one in the hero). The
 * AI's own read (`aiReview.verdict`) can disagree with it — e.g. a package
 * confirmed MALICIOUS by threat intel where the code the AI read looks
 * harmless on its own. Per FUTURE_SCOPE.md's "one source of truth" lesson,
 * the AI can never downgrade hard evidence, so when they disagree this
 * shows an explicit callout saying which one wins and why, rather than
 * silently showing two badges a reader has to reconcile themselves.
 */
export function AiReviewSection({
  aiReview,
  aiError,
  aiFailed,
  finalVerdict,
}: {
  aiReview?: AIReview | null;
  aiError?: string | null;
  aiFailed?: boolean;
  finalVerdict?: Verdict | null;
}) {
  if (!aiReview) {
    if (aiFailed || aiError) {
      return (
        <section className="flex flex-col gap-2 rounded-lg border border-border bg-card/40 p-6">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Sparkles className="size-4 text-brand" />
            AI review
          </div>
          <p className="text-sm text-muted-foreground">
            The AI reviewer could not finish{aiError ? `: ${aiError}` : "."} The verdict above
            falls back to automated rules only.
          </p>
        </section>
      );
    }
    return null;
  }

  const paragraphs = aiReview.reasoning
    ? aiReview.reasoning.split(/\n{2,}/).filter(Boolean)
    : [];

  const overridden = !!finalVerdict && finalVerdict !== aiReview.verdict;
  const finalStyle = overridden ? verdictStyle(finalVerdict) : null;

  return (
    <section className="flex flex-col gap-4 rounded-lg border border-brand/20 bg-gradient-to-br from-accent/40 to-transparent p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Sparkles className="size-4 text-brand" />
          AI review
          {aiReview.mode && (
            <span className="rounded-full border border-border bg-background/70 px-2 py-0.5 text-[11px] font-medium text-muted-foreground">
              {aiReview.mode === "deep_dive" ? "Deep dive" : "Quick look"}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-muted-foreground">The AI thought:</span>
          <VerdictBadge verdict={aiReview.verdict} size="sm" />
          <ConfidencePill confidence={aiReview.confidence} />
        </div>
      </div>

      {overridden && finalStyle && (
        <div className={`flex items-start gap-2.5 rounded-xl border px-4 py-3 text-sm ${finalStyle.badgeClass}`}>
          <ShieldAlert className="mt-0.5 size-4 shrink-0" />
          <p>
            <span className="font-semibold">PkgGuard&apos;s final verdict is {finalStyle.shortLabel.toLowerCase()}</span>,
            not what the AI read below. Threat intelligence and other hard evidence always outrank the AI&apos;s
            own read of the code — the AI never gets to downgrade a confirmed threat.
          </p>
        </div>
      )}

      {aiReview.summary && <p className="text-sm font-medium text-foreground">{aiReview.summary}</p>}

      {paragraphs.length > 0 && (
        <div className="flex flex-col gap-2.5 text-sm leading-relaxed text-foreground/85">
          {paragraphs.map((p, i) => (
            <p key={i}>{p}</p>
          ))}
        </div>
      )}

      {aiReview.evidence && aiReview.evidence.length > 0 && (
        <div className="flex flex-col gap-2">
          <span className="text-xs font-semibold text-muted-foreground">Evidence it read</span>
          <ul className="flex flex-col gap-1.5">
            {aiReview.evidence.map((e, i) => (
              <li key={i} className="flex gap-2 rounded-lg border border-border/70 bg-background/50 px-3 py-2 text-xs">
                <span className="shrink-0 font-mono text-muted-foreground">
                  {e.file}
                  {e.line ? `:${e.line}` : ""}
                </span>
                <span className="text-foreground/80">{e.explanation}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex flex-wrap items-center gap-x-5 gap-y-1.5 border-t border-border/60 pt-3 text-xs text-muted-foreground">
        {aiReview.model && (
          <span className="inline-flex items-center gap-1.5">
            <Sparkles className="size-3.5" />
            {aiReview.model}
          </span>
        )}
        {aiReview.filesRead && aiReview.filesRead.length > 0 && (
          <span className="inline-flex items-center gap-1.5">
            <FileText className="size-3.5" />
            Read {aiReview.filesRead.length} file{aiReview.filesRead.length !== 1 ? "s" : ""}
          </span>
        )}
        {typeof aiReview.toolCalls === "number" && (
          <span className="inline-flex items-center gap-1.5">
            <Wrench className="size-3.5" />
            {aiReview.toolCalls} tool call{aiReview.toolCalls !== 1 ? "s" : ""}
          </span>
        )}
        {typeof aiReview.durationSeconds === "number" && (
          <span className="inline-flex items-center gap-1.5">
            <Clock className="size-3.5" />
            {aiReview.durationSeconds.toFixed(1)}s
          </span>
        )}
      </div>
    </section>
  );
}

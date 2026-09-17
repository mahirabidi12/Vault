import { codeToHtml } from "shiki";
import { langForFile } from "@/lib/lang-for-file";
import { FileCode2 } from "lucide-react";
import { cn } from "@/lib/utils";

export type EvidenceTone = "threat" | "warn" | "neutral";

const TONE_BORDER: Record<EvidenceTone, string> = {
  threat: "border-malicious/35",
  warn: "border-suspicious/30",
  neutral: "border-border",
};

const TONE_HEADER: Record<EvidenceTone, string> = {
  threat: "bg-malicious-bg/70 text-malicious",
  warn: "bg-suspicious-bg/70 text-suspicious",
  neutral: "bg-muted/60 text-muted-foreground",
};

const TONE_MARKER: Record<EvidenceTone, string> = {
  threat: "text-malicious",
  warn: "text-suspicious",
  neutral: "text-muted-foreground/50",
};

/**
 * Renders one finding's evidence line with real syntax highlighting
 * (Shiki, dual light/dark theme baked into one render — see the
 * `.shiki`/`.dark .shiki` rules in globals.css for how the toggle works).
 *
 * `tone` turns this into a "special box" per BRIEF: a HIGH-severity finding
 * on a malicious package gets a red-tinted frame and a `→` pointer on the
 * flagged line's gutter, a MEDIUM warning gets amber, everything else stays
 * neutral so LOW findings don't compete for attention.
 */
export async function CodeEvidence({
  file,
  line,
  snippet,
  tone = "neutral",
  className,
}: {
  file?: string | null;
  line?: number | null;
  snippet?: string | null;
  tone?: EvidenceTone;
  className?: string;
}) {
  if (!snippet) return null;

  const html = await codeToHtml(snippet, {
    lang: langForFile(file),
    themes: { light: "github-light", dark: "github-dark-dimmed" },
    defaultColor: false,
  });

  return (
    <div className={cn("overflow-hidden rounded-lg border bg-card", TONE_BORDER[tone], className)}>
      {file && (
        <div className={cn("flex items-center gap-1.5 border-b px-3 py-1.5 font-mono text-xs", TONE_BORDER[tone], TONE_HEADER[tone])}>
          <FileCode2 className="size-3.5 shrink-0" />
          <span className="truncate">{file}</span>
          {line ? <span className="opacity-70">:{line}</span> : null}
        </div>
      )}
      <div className="flex">
        <div
          className={cn(
            "flex shrink-0 select-none items-start justify-end gap-1 py-2.5 pr-2 pl-3 font-mono text-[13px] leading-relaxed",
            tone !== "neutral" && (tone === "threat" ? "bg-malicious-bg/25" : "bg-suspicious-bg/25")
          )}
        >
          <span className={cn("font-semibold", TONE_MARKER[tone])}>{tone !== "neutral" ? "→" : ""}</span>
          <span className="text-muted-foreground/50">{line ?? ""}</span>
        </div>
        <div
          className="evidence-code min-w-0 flex-1 overflow-x-auto py-2.5 pr-3 text-[13px] leading-relaxed [&_pre]:!bg-transparent [&_pre]:whitespace-pre-wrap [&_pre]:break-all"
          dangerouslySetInnerHTML={{ __html: html }}
        />
      </div>
    </div>
  );
}

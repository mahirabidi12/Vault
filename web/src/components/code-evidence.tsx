import { codeToHtml } from "shiki";
import { langForFile } from "@/lib/lang-for-file";
import { FileCode2 } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Renders one finding's evidence line with real syntax highlighting
 * (Shiki, dual light/dark theme baked into one render — see the
 * `.shiki`/`.dark .shiki` rules in globals.css for how the toggle works).
 */
export async function CodeEvidence({
  file,
  line,
  snippet,
  className,
}: {
  file?: string | null;
  line?: number | null;
  snippet?: string | null;
  className?: string;
}) {
  if (!snippet) return null;

  const html = await codeToHtml(snippet, {
    lang: langForFile(file),
    themes: { light: "github-light", dark: "github-dark-dimmed" },
    defaultColor: false,
  });

  return (
    <div className={cn("overflow-hidden rounded-lg border border-border bg-card", className)}>
      {file && (
        <div className="flex items-center gap-1.5 border-b border-border bg-muted/60 px-3 py-1.5 font-mono text-xs text-muted-foreground">
          <FileCode2 className="size-3.5 shrink-0" />
          <span className="truncate">{file}</span>
          {line ? <span className="text-muted-foreground/70">:{line}</span> : null}
        </div>
      )}
      <div
        className="evidence-code overflow-x-auto px-3 py-2.5 text-[13px] leading-relaxed [&_pre]:!bg-transparent [&_pre]:whitespace-pre-wrap [&_pre]:break-all"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </div>
  );
}

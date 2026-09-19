import { CopyButton } from "@/components/copy-button";
import { cn } from "@/lib/utils";

/** A code sample with a language label and a copy button. */
export function CodeBlock({ code, lang, className }: { code: string; lang?: string; className?: string }) {
  return (
    <div className={cn("overflow-hidden rounded-2xl border border-white/10 bg-[#07080b]", className)}>
      <div className="flex items-center justify-between border-b border-white/10 bg-white/[0.03] px-4 py-1.5">
        <span className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">{lang ?? "text"}</span>
        <CopyButton value={code} className="h-7 text-zinc-400 hover:bg-white/10 hover:text-white" />
      </div>
      <pre className="overflow-x-auto p-4 font-mono text-[13px] leading-relaxed text-zinc-200">{code}</pre>
    </div>
  );
}

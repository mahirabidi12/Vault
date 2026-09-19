import { CopyButton } from "@/components/copy-button";
import { cn } from "@/lib/utils";

export function TerminalBlock({
  command,
  label,
  className,
  wrap,
}: {
  command: string;
  label?: string;
  className?: string;
  /** Let a long command wrap onto a second line instead of scrolling sideways. */
  wrap?: boolean;
}) {
  return (
    <div
      className={cn(
        "group flex items-center justify-between gap-3 rounded-xl border border-border bg-[#0b0b12] px-4 py-3 font-mono text-sm text-zinc-100 shadow-sm dark:border-white/10",
        className
      )}
    >
      <div className={cn("flex min-w-0 gap-2", wrap ? "items-start" : "items-center overflow-x-auto")}>
        <span className="shrink-0 select-none text-zinc-500">{label ?? "$"}</span>
        <code className={cn("text-zinc-100", wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre")}>{command}</code>
      </div>
      <CopyButton
        value={command}
        className="shrink-0 text-zinc-400 hover:bg-white/10 hover:text-white"
      />
    </div>
  );
}

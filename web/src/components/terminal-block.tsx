import { CopyButton } from "@/components/copy-button";
import { cn } from "@/lib/utils";

export function TerminalBlock({
  command,
  label,
  className,
}: {
  command: string;
  label?: string;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "group flex items-center justify-between gap-3 rounded-xl border border-border bg-[#0b0b12] px-4 py-3 font-mono text-sm text-zinc-100 shadow-sm dark:border-white/10",
        className
      )}
    >
      <div className="flex min-w-0 items-center gap-2 overflow-x-auto">
        <span className="shrink-0 select-none text-zinc-500">{label ?? "$"}</span>
        <code className="whitespace-pre text-zinc-100">{command}</code>
      </div>
      <CopyButton
        value={command}
        className="shrink-0 text-zinc-400 hover:bg-white/10 hover:text-white"
      />
    </div>
  );
}

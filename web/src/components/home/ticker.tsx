import { cn } from "@/lib/utils";

const ITEMS: { name: string; verdict: "ok" | "sus" | "bad" }[] = [
  { name: "express@4.21.2", verdict: "ok" },
  { name: "left-pad-pro@1.0.3", verdict: "bad" },
  { name: "zod@4.6.5", verdict: "ok" },
  { name: "colors-js@2.1.0", verdict: "sus" },
  { name: "chalk@6.0.0", verdict: "ok" },
  { name: "lodash@4.17.21", verdict: "ok" },
  { name: "event-stream-x@3.3.6", verdict: "bad" },
  { name: "esbuild@0.28.2", verdict: "ok" },
  { name: "picocolors@1.1.1", verdict: "ok" },
  { name: "node-ipc-fork@9.2.2", verdict: "sus" },
];
const TONE = { ok: "bg-safe", sus: "bg-suspicious", bad: "bg-malicious" };
const TEXT = { ok: "No issues found", sus: "Suspicious", bad: "Malicious" };

export function Ticker({ className }: { className?: string }) {
  const row = [...ITEMS, ...ITEMS];
  return (
    <div className={cn("relative overflow-hidden border-y border-border/60 py-6 [mask-image:linear-gradient(to_right,transparent,black_12%,black_88%,transparent)]", className)}>
      <div className="animate-marquee flex w-max gap-3">
        {row.map((it, i) => (
          <span key={i} className="flex shrink-0 items-center gap-2.5 rounded-full border border-border bg-card/70 px-5 py-3 font-mono text-sm">
            <span className={`size-2 rounded-full ${TONE[it.verdict]}`} />
            <span className="text-foreground">{it.name}</span>
            <span className="text-muted-foreground">{TEXT[it.verdict]}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

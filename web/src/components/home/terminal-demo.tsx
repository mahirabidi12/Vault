"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

export type DemoLine = { text: string; tone?: "ok" | "bad" | "warn" | "dim" };

const TONE = {
  ok: "text-safe",
  bad: "text-malicious",
  warn: "text-suspicious",
  dim: "text-zinc-500",
} as const;

export function TerminalDemo({ lines, title }: { lines: DemoLine[]; title: string }) {
  const [shown, setShown] = React.useState(lines.length);

  React.useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    setShown(0);
    let n = 0;
    const id = setInterval(() => {
      n += 1;
      if (n > lines.length + 4) n = 0;
      setShown(Math.min(n, lines.length));
    }, 750);
    return () => clearInterval(id);
  }, [lines.length]);

  return (
    <div className="overflow-hidden rounded-xl border border-white/10 bg-[#070709]">
      <div className="flex items-center gap-1.5 border-b border-white/10 px-3 py-2">
        <span className="size-2 rounded-full bg-white/15" />
        <span className="size-2 rounded-full bg-white/15" />
        <span className="size-2 rounded-full bg-white/15" />
        <span className="ml-2 font-mono text-[11px] text-zinc-500">{title}</span>
      </div>
      <div className="min-h-[132px] px-4 py-3 font-mono text-[12.5px] leading-6">
        {lines.slice(0, shown).map((l, i) => (
          <div key={i} className={cn("animate-fade-up whitespace-pre-wrap", TONE[l.tone ?? "dim"], !l.tone && "text-zinc-200")}>
            {l.text}
          </div>
        ))}
        {shown < lines.length && <span className="inline-block h-4 w-2 translate-y-0.5 animate-pulse bg-zinc-300" />}
      </div>
    </div>
  );
}

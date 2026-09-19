"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { useDemoClock } from "@/components/home/demo-clock";

export type DemoLine = { text: string; tone?: "ok" | "bad" | "warn" | "dim" };

const TONE = {
  ok: "text-safe",
  bad: "text-malicious",
  warn: "text-suspicious",
  dim: "text-zinc-500",
} as const;

/** A scripted terminal session driven by the shared demo clock. New lines appear at the bottom, like a real terminal. */
export function TerminalDemo({ scenarios, title, height = 290 }: { scenarios: DemoLine[][]; title: string; height?: number }) {
  const { scenario, step, started } = useDemoClock();
  const lines = scenarios[scenario % scenarios.length];
  const shown = started ? Math.min(step, lines.length) : 0;
  const body = React.useRef<HTMLDivElement>(null);

  // Lines fill from the top down; only once the window is full does it follow the newest line, like a real terminal.
  React.useEffect(() => {
    const el = body.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [shown, scenario]);

  return (
    <div className="overflow-hidden rounded-xl border border-white/10 bg-[#070709]">
      <div className="flex items-center gap-1.5 border-b border-white/10 px-3 py-1.5">
        <span className="size-2 rounded-full bg-white/15" />
        <span className="size-2 rounded-full bg-white/15" />
        <span className="size-2 rounded-full bg-white/15" />
        <span className="ml-2 font-mono text-[11px] text-zinc-500">{title}</span>
      </div>
      <div ref={body} className="overflow-hidden px-3.5 py-2.5 font-mono text-[11.5px] leading-[1.5]" style={{ height }}>
        {lines.slice(0, shown).map((l, i) => (
          <div key={`${scenario}-${i}`} className={cn("animate-fade-up min-h-[1.5em] shrink-0 whitespace-pre-wrap break-words", TONE[l.tone ?? "dim"], !l.tone && "text-zinc-200")}>
            {l.text}
          </div>
        ))}
        {shown < lines.length && <span className="inline-block h-3.5 w-1.5 shrink-0 animate-pulse bg-zinc-300" />}
      </div>
    </div>
  );
}

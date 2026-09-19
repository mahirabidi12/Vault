"use client";

import * as React from "react";
import { Box, ListChecks, FileSearch, Radar, ShieldCheck, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";

export type TraceStage = {
  key: "intel" | "info" | "static" | "sandbox" | "ai" | "verdict";
  title: string;
  headline: string;
  detail: string;
  tone: "ok" | "warn" | "bad" | "muted";
};

const ICONS = { intel: Radar, info: ListChecks, static: FileSearch, sandbox: Box, ai: Sparkles, verdict: ShieldCheck };

const TONE = {
  ok: { text: "text-safe", ring: "border-safe/50 bg-safe/10", glow: "rgba(52,211,153,0.35)" },
  warn: { text: "text-suspicious", ring: "border-suspicious/50 bg-suspicious/10", glow: "rgba(251,191,36,0.35)" },
  bad: { text: "text-malicious", ring: "border-malicious/50 bg-malicious/10", glow: "rgba(248,81,73,0.4)" },
  muted: { text: "text-muted-foreground", ring: "border-white/15 bg-white/5", glow: "rgba(255,255,255,0.1)" },
} as const;

/** The checks that produced this verdict, lighting up one after another when scrolled into view. */
export function PipelineTrace({ stages }: { stages: TraceStage[] }) {
  const ref = React.useRef<HTMLDivElement>(null);
  const [lit, setLit] = React.useState(stages.length);

  React.useEffect(() => {
    const el = ref.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    let timer: ReturnType<typeof setInterval> | null = null;
    const io = new IntersectionObserver(
      ([e]) => {
        if (!e.isIntersecting) return;
        io.disconnect();
        setLit(0);
        let n = 0;
        timer = setInterval(() => {
          n += 1;
          setLit(n);
          if (n >= stages.length && timer) clearInterval(timer);
        }, 520);
      },
      { threshold: 0.3 }
    );
    io.observe(el);
    return () => {
      io.disconnect();
      if (timer) clearInterval(timer);
    };
  }, [stages.length]);

  const progress = stages.length > 1 ? Math.min(1, Math.max(0, (lit - 0.5) / (stages.length - 1))) : 1;

  return (
    <section ref={ref} className="flex flex-col gap-5">
      <div>
        <p className="kicker text-brand">How we got here</p>
        <h2 className="mt-1 font-display text-xl font-semibold tracking-tight sm:text-2xl">Every check this package went through</h2>
      </div>

      <div className="relative">
        {/* connector, filling as stages light up */}
        <div aria-hidden className="absolute left-[calc(100%/12)] right-[calc(100%/12)] top-[26px] hidden h-px bg-white/10 lg:block">
          <div
            className="h-full bg-gradient-to-r from-white/30 to-white shadow-[0_0_12px_rgba(255,255,255,0.6)] transition-[width] duration-500 ease-out"
            style={{ width: `${progress * 100}%` }}
          />
        </div>

        <ol className="grid gap-3 sm:grid-cols-2 lg:grid-cols-6 lg:gap-2">
          {stages.map((s, i) => {
            const on = i < lit;
            const active = i === lit - 1;
            const Icon = ICONS[s.key];
            const tone = TONE[s.tone];
            return (
              <li key={s.key} className="relative flex flex-col items-center gap-3 text-center lg:px-1">
                <span
                  className={cn(
                    "relative z-10 flex size-[52px] items-center justify-center rounded-2xl border transition-all duration-500",
                    on ? tone.ring : "border-white/10 bg-black",
                    on ? tone.text : "text-zinc-600",
                    on && "scale-100",
                    !on && "scale-90"
                  )}
                  style={on ? { boxShadow: `0 0 ${active ? 30 : 14}px ${tone.glow}` } : undefined}
                >
                  <Icon className="size-5" />
                  {active && <span aria-hidden className="ping-ring absolute inset-0 rounded-2xl border" style={{ borderColor: tone.glow }} />}
                </span>
                <div
                  className={cn(
                    "w-full rounded-2xl border p-3.5 transition-all duration-500 sm:min-h-[8.5rem]",
                    on ? "border-white/15 bg-white/[0.04] opacity-100" : "translate-y-1 border-white/5 bg-transparent opacity-40"
                  )}
                >
                  <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                    {i + 1} · {s.title}
                  </p>
                  <p className={cn("mt-1.5 text-[15px] font-semibold leading-tight", on ? tone.text : "text-zinc-600")}>{s.headline}</p>
                  <p className="mt-1 text-xs leading-snug text-muted-foreground">{s.detail}</p>
                </div>
              </li>
            );
          })}
        </ol>
      </div>
    </section>
  );
}

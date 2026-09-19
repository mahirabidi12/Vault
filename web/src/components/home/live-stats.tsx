"use client";

import * as React from "react";
import { CountUp } from "@/components/count-up";
import { useStats } from "@/lib/queries";
import { Skeleton } from "@/components/ui/skeleton";
import { ShieldCheck, ShieldAlert, ShieldX, ScanSearch } from "lucide-react";
import { cn } from "@/lib/utils";

const RING_R = 46;
const RING_LEN = 2 * Math.PI * RING_R;

type Tone = "safe" | "suspicious" | "malicious";

const TONES: Record<Tone, { label: string; icon: typeof ShieldCheck; text: string; color: string }> = {
  safe: { label: "No issues found", icon: ShieldCheck, text: "text-safe", color: "var(--safe)" },
  suspicious: { label: "Suspicious", icon: ShieldAlert, text: "text-suspicious", color: "var(--suspicious)" },
  malicious: { label: "Malicious caught", icon: ShieldX, text: "text-malicious", color: "var(--malicious)" },
};

export function LiveStats() {
  const { data, isLoading } = useStats();
  const total = data?.totalScanned ?? 0;
  const parts: { tone: Tone; value: number }[] = [
    { tone: "safe", value: data?.safeCount ?? 0 },
    { tone: "suspicious", value: data?.suspiciousCount ?? 0 },
    { tone: "malicious", value: data?.maliciousCount ?? 0 },
  ];
  const sum = Math.max(1, parts.reduce((s, p) => s + p.value, 0));

  return (
    <div className="flex flex-col gap-4">
      <dl className="grid gap-4 sm:grid-cols-2 lg:grid-cols-[1.35fr_1fr_1fr_1fr]">
        {/* the big one */}
        <div className="group relative isolate overflow-hidden rounded-3xl border border-white/12 bg-white/[0.03] p-6 transition-all duration-500 hover:-translate-y-1 hover:border-white/30 sm:col-span-2 sm:p-7 lg:col-span-1">
          <div aria-hidden className="blob-drift pointer-events-none absolute -left-10 -top-16 -z-10 size-56 rounded-full bg-brand/20 blur-3xl" />
          <div aria-hidden className="bg-grid pointer-events-none absolute inset-0 -z-10 opacity-40 [mask-image:radial-gradient(ellipse_80%_80%_at_20%_20%,black,transparent)]" />
          <div className="flex items-center justify-between">
            <span className="flex size-11 items-center justify-center rounded-2xl border border-white/10 bg-black/40">
              <ScanSearch className="size-5" />
            </span>
            <span className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-black/40 px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-muted-foreground">
              <span className="relative flex size-2">
                <span className="ping-ring absolute inline-flex size-full rounded-full bg-safe" />
                <span className="relative inline-flex size-2 rounded-full bg-safe" />
              </span>
              Live
            </span>
          </div>
          <div className="mt-8">
            {isLoading ? (
              <Skeleton className="h-14 w-40" />
            ) : (
              <dd className="font-display text-[clamp(3rem,6vw,4.5rem)] font-semibold leading-none tracking-[-0.05em] tabular-nums">
                <CountUp value={total} duration={1600} />
              </dd>
            )}
            <dt className="mt-2 text-sm text-muted-foreground">Packages scanned</dt>
            <p className="mt-1 text-xs text-muted-foreground/70">Each one is instant for the next person who asks.</p>
          </div>
          <div aria-hidden className="mt-6 flex h-10 items-end gap-1">
            {Array.from({ length: 28 }).map((_, i) => (
              <span
                key={i}
                className="eq-bar w-full rounded-full bg-gradient-to-t from-white/10 to-white/60"
                style={{ height: `${30 + ((i * 37) % 70)}%`, animationDelay: `${(i * 90) % 1600}ms`, animationDuration: `${1300 + ((i * 53) % 900)}ms` }}
              />
            ))}
          </div>
        </div>

        {parts.map(({ tone, value }, idx) => {
          const t = TONES[tone];
          const pct = total > 0 ? value / total : 0;
          return (
            <div
              key={tone}
              style={{ animationDelay: `${idx * 120}ms` }}
              className="rise-in group relative isolate flex flex-col items-center gap-4 overflow-hidden rounded-3xl border border-white/12 bg-white/[0.03] p-6 text-center transition-all duration-500 hover:-translate-y-1 hover:border-white/30"
            >
              <div
                aria-hidden
                className="blob-drift pointer-events-none absolute -top-16 left-1/2 -z-10 size-48 -translate-x-1/2 rounded-full blur-3xl [animation-delay:-4s]"
                style={{ background: `color-mix(in oklch, ${t.color}, transparent 82%)` }}
              />
              <div className="relative flex size-32 items-center justify-center">
                <span aria-hidden className="ping-ring absolute size-20 rounded-full border" style={{ borderColor: `color-mix(in oklch, ${t.color}, transparent 60%)` }} />
                <svg viewBox="0 0 108 108" className="absolute inset-0 size-full -rotate-90" aria-hidden>
                  <circle cx="54" cy="54" r={RING_R} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="6" />
                  {!isLoading && (
                    <circle
                      cx="54"
                      cy="54"
                      r={RING_R}
                      fill="none"
                      stroke={t.color}
                      strokeWidth="6"
                      strokeLinecap="round"
                      strokeDasharray={RING_LEN}
                      className="ring-fill"
                      style={{ "--ring-len": RING_LEN, "--ring-to": RING_LEN * (1 - Math.max(pct, value > 0 ? 0.03 : 0)), filter: `drop-shadow(0 0 6px ${t.color})` } as React.CSSProperties}
                    />
                  )}
                </svg>
                <t.icon className={cn("size-9", t.text)} strokeWidth={1.6} />
              </div>
              <div>
                {isLoading ? (
                  <Skeleton className="mx-auto h-9 w-20" />
                ) : (
                  <dd className={cn("font-display text-4xl font-semibold tracking-tight tabular-nums", t.text)}>
                    <CountUp value={value} duration={1400} />
                  </dd>
                )}
                <dt className="mt-1 text-sm text-muted-foreground">{t.label}</dt>
                {!isLoading && total > 0 && (
                  <p className="mt-0.5 font-mono text-xs text-muted-foreground/70">{(pct * 100).toFixed(pct > 0 && pct < 0.1 ? 1 : 0)}% of all scans</p>
                )}
              </div>
            </div>
          );
        })}
      </dl>

      {/* distribution */}
      {!isLoading && total > 0 && (
        <div className="rounded-2xl border border-white/10 bg-white/[0.02] p-4">
          <div className="flex h-3 w-full gap-1 overflow-hidden rounded-full" aria-hidden>
            {parts.map(({ tone, value }) =>
              value > 0 ? (
                <div
                  key={tone}
                  className="grow-x h-full rounded-full"
                  style={{ width: `${(value / sum) * 100}%`, background: TONES[tone].color, boxShadow: `0 0 12px ${TONES[tone].color}` }}
                />
              ) : null
            )}
          </div>
          <p className="mt-3 flex flex-wrap justify-center gap-x-5 gap-y-1 text-xs text-muted-foreground">
            {parts.map(({ tone, value }) => (
              <span key={tone} className="inline-flex items-center gap-1.5">
                <span className="size-2 rounded-full" style={{ background: TONES[tone].color }} />
                {TONES[tone].label}: {value.toLocaleString()}
              </span>
            ))}
          </p>
        </div>
      )}
    </div>
  );
}

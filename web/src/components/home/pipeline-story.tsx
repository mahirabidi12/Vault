"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { PipelineTerminal } from "@/components/home/pipeline-terminal";
import { Download, Radar, Code2, Sparkles, ShieldCheck } from "lucide-react";

export type StepId = "fetch" | "intel" | "code" | "ai" | "verdict";

type Beat = {
  id: StepId;
  icon: typeof Download;
  kicker: string;
  title: string;
  body: string;
};

const BEATS: Beat[] = [
  {
    id: "fetch",
    icon: Download,
    kicker: "Step 1 — fetch",
    title: "Download the exact artifact, verified.",
    body: "PkgGuard pulls the published tarball straight from the npm registry and checks it against the registry's own integrity hash before reading a single byte.",
  },
  {
    id: "intel",
    icon: Radar,
    kicker: "Step 2 — threat intel",
    title: "Check what's already known.",
    body: "OSV.dev and SafeDep are checked for existing malware advisories. A known-malicious match ends the scan right here — no code needs to be read at all.",
  },
  {
    id: "code",
    icon: Code2,
    kicker: "Step 3 — code & package info",
    title: "Read what it actually does.",
    body: "Install scripts, source code and metadata are scanned for red flags: dynamic code, secret-reading, network calls out of install scripts, typosquats, brand-new maintainers.",
  },
  {
    id: "ai",
    icon: Sparkles,
    kicker: "Step 4 — AI triage",
    title: "A second opinion, on the real code.",
    body: "When something looks off, an AI agent reads the flagged files in context and explains, in plain language, whether the behavior is expected or actually dangerous.",
  },
  {
    id: "verdict",
    icon: ShieldCheck,
    kicker: "Step 5 — verdict",
    title: "One verdict, with every reason attached.",
    body: "Safe, suspicious or malicious — never a guess, always traceable back to the exact rule, intel source, or AI read that decided it.",
  },
];

export function PipelineStory() {
  const [active, setActive] = React.useState<StepId>("fetch");
  const refs = React.useRef<Map<StepId, HTMLElement>>(new Map());

  React.useEffect(() => {
    const pick = () => {
      const target = window.innerHeight * 0.5;
      let best: { id: StepId; distance: number } | null = null;
      for (const [id, el] of refs.current) {
        const rect = el.getBoundingClientRect();
        const distance = Math.abs(rect.top + rect.height / 2 - target);
        if (!best || distance < best.distance) best = { id, distance };
      }
      if (best) setActive(best.id);
    };
    pick();
    window.addEventListener("scroll", pick, { passive: true });
    window.addEventListener("resize", pick);
    return () => {
      window.removeEventListener("scroll", pick);
      window.removeEventListener("resize", pick);
    };
  }, []);

  return (
    <section id="how-it-works" className="scroll-mt-16 py-24 sm:py-32">
      <div className="rise mx-auto max-w-2xl px-4 text-center sm:px-6">
        <p className="kicker text-brand">How a verdict gets decided</p>
        <h2 className="mt-3 font-display text-[clamp(1.9rem,4.2vw,3rem)] leading-[1.05] font-semibold tracking-tight">
          Nothing is ever labeled safe on a guess.
        </h2>
        <p className="mt-4 text-muted-foreground">
          Every scan walks the same five steps, and every step leaves evidence in the final report.
        </p>
      </div>

      {/* Mobile: static terminal, then beats stacked normally */}
      <div className="mx-auto mt-12 max-w-lg px-4 lg:hidden">
        <PipelineTerminal active="verdict" />
      </div>
      <ol className="mx-auto mt-10 flex max-w-lg flex-col gap-12 px-4 lg:hidden">
        {BEATS.map((beat) => (
          <li key={beat.id}>
            <BeatContent beat={beat} />
          </li>
        ))}
      </ol>

      {/* Desktop: sticky terminal beside scroll-tracked narrative */}
      <div className="mx-auto mt-16 hidden max-w-6xl gap-16 px-6 lg:grid lg:grid-cols-12">
        <ol className="flex flex-col lg:col-span-6">
          {BEATS.map((beat) => (
            <li
              key={beat.id}
              ref={(el) => {
                if (el) refs.current.set(beat.id, el);
                else refs.current.delete(beat.id);
              }}
              className={cn(
                "flex min-h-[46vh] flex-col justify-center transition-opacity duration-500",
                active === beat.id ? "opacity-100" : "opacity-60"
              )}
            >
              <BeatContent beat={beat} active={active === beat.id} />
            </li>
          ))}
        </ol>
        <div className="lg:col-span-6">
          <div className="sticky top-24 flex items-center">
            <PipelineTerminal active={active} className="w-full" />
          </div>
        </div>
      </div>
    </section>
  );
}

function BeatContent({ beat, active }: { beat: Beat; active?: boolean }) {
  return (
    <>
      <span
        className={cn(
          "mb-4 flex size-10 items-center justify-center rounded-lg border transition-colors",
          active ? "border-brand/40 bg-brand/10 text-brand" : "border-border bg-card text-muted-foreground"
        )}
      >
        <beat.icon className="size-4.5" />
      </span>
      <p className="kicker text-brand">{beat.kicker}</p>
      <h3 className="mt-2 font-display text-[clamp(1.4rem,2.2vw,1.9rem)] font-semibold leading-tight">{beat.title}</h3>
      <p className="mt-3 max-w-md text-[15px] leading-relaxed text-muted-foreground">{beat.body}</p>
    </>
  );
}

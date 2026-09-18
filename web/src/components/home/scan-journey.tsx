"use client";

import * as React from "react";
import { BrainCircuit, Eye, Play } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  RAIL,
  SANDBOX_LIMITS,
  SANDBOX_LIVE,
  STAGES,
  clamp01,
  journeyHeightVh,
  locate,
  stageStart,
  type StageId,
} from "@/lib/pipeline-flow";
import { AiScene, FetchScene, ForkScene, InfoScene, IntelScene, VerdictScene } from "@/components/home/journey-scenes";

type Copy = { kicker: string; title: string; body: string };

const COPY: Record<StageId, Copy> = {
  fetch: {
    kicker: "Step 1 · fetch & verify",
    title: "We download the exact package and prove it's untouched.",
    body: "The tarball comes straight from npm and is checked against the registry's own hash before we read a byte. Unpacking is safe: no path tricks, no links, size caps.",
  },
  intel: {
    kicker: "Step 2 · threat intel",
    title: "First, what does the world already know?",
    body: "OSV.dev and SafeDep already track a lot of malware. A known match decides the verdict on the spot, and nothing can override it.",
  },
  info: {
    kicker: "Step 3 · package info",
    title: "Then, does the package itself look off?",
    body: "Install scripts, a package published hours ago, a brand-new publisher, a missing repository. One flag means little. Several together mean a closer look.",
  },
  fork: {
    kicker: "Steps 4 + 5 · at the same time",
    title: "We read it. And we run it.",
    body: "The static scan parses the code as text and never runs it. In parallel, the sandbox installs and runs the package in a locked box with no internet, and records everything it tries to do.",
  },
  ai: {
    kicker: "Step 6 · AI review",
    title: "An AI reads the code and the recording together.",
    body: "It explains in plain English what is normal and what is dangerous. It can raise an alarm the rules missed, or clear a false one. It cannot clear proof-grade evidence.",
  },
  verdict: {
    kicker: "Step 7 · verdict",
    title: "One verdict, every reason attached.",
    body: "Safe (shown as “No issues found”), suspicious or malicious, with who decided it and the exact rule, log line or code behind it.",
  },
};

export function ScanJourney() {
  const ref = React.useRef<HTMLElement>(null);
  const [progress, setProgress] = React.useState(0);
  // The scene on screen lags the scroll position: it fades out, swaps, then fades in.
  const [shownIndex, setShownIndex] = React.useState(0);
  const [fading, setFading] = React.useState(false);

  React.useEffect(() => {
    let raf = 0;
    let shown = 0;
    let swapTimer: ReturnType<typeof setTimeout> | null = null;
    let target = 0;
    let current = 0;
    const read = () => {
      const el = ref.current;
      if (!el) return;
      const rect = el.getBoundingClientRect();
      const span = rect.height - window.innerHeight;
      target = span > 0 ? clamp01(-rect.top / span) : 0;
    };
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const tick = () => {
      read();
      const diff = target - current;
      // Ease toward the scroll position so fast wheel flicks play out smoothly.
      const next = reduce || Math.abs(diff) < 0.0003 ? target : current + diff * 0.07;
      if (next !== current) setProgress(next);
      current = next;
      const live = locate(current).index;
      if (live !== shown && !swapTimer) {
        setFading(true);
        swapTimer = setTimeout(() => {
          shown = locate(current).index;
          setShownIndex(shown);
          setFading(false);
          swapTimer = null;
        }, 280);
      }
      raf = requestAnimationFrame(tick);
    };
    read();
    current = target;
    raf = requestAnimationFrame(tick);
    return () => {
      cancelAnimationFrame(raf);
      if (swapTimer) clearTimeout(swapTimer);
    };
  }, []);

  const { index, t } = locate(progress);
  const stage = STAGES[index];
  const shownStage = STAGES[shownIndex];
  const sceneT = shownIndex === index ? t : shownIndex < index ? 1 : 0;
  const copy = COPY[shownStage.id];
  const isFork = shownStage.id === "fork";

  const jumpTo = (stageId: StageId) => {
    const el = ref.current;
    if (!el) return;
    const i = STAGES.findIndex((s) => s.id === stageId);
    const span = el.offsetHeight - window.innerHeight;
    const top = el.getBoundingClientRect().top + window.scrollY + stageStart(i) * span + 4;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    window.scrollTo({ top, behavior: reduce ? "auto" : "smooth" });
  };

  return (
    <div id="how-it-works" className="scroll-mt-16">
      <div className="mx-auto max-w-3xl px-4 pt-24 text-center sm:px-6 sm:pt-32">
        <p className="kicker text-brand">How a package gets tested</p>
        <h2 className="mt-3 font-display text-[clamp(1.9rem,4.4vw,3.2rem)] font-semibold leading-[1.05] tracking-[-0.04em]">
          Nothing is labeled safe on a guess.
        </h2>
        <p className="mt-4 text-muted-foreground">
          Scroll to watch one package go through everything we do to it, from the first download to the final verdict.
        </p>
      </div>

      <ThreeWays />

      <section ref={ref} aria-label="How a package gets tested, step by step" style={{ height: `${journeyHeightVh}vh` }} className="relative mt-16">
        <div className="sticky top-0 flex h-[100svh] flex-col overflow-hidden pt-[68px]">
          <Glow stage={stage.id} t={t} />

          {/* Progress rail */}
          <Rail stage={stage.id} index={index} t={t} onJump={jumpTo} />

          {/* Stage */}
          <div
            className={cn(
              "relative mx-auto flex min-h-0 w-full max-w-6xl flex-1 flex-col px-4 pb-5 pt-3 transition-[opacity,transform] duration-300 ease-out sm:px-6 sm:pb-8",
              fading ? "translate-y-2 opacity-0" : "translate-y-0 opacity-100"
            )}
          >
            {isFork ? (
              <div className="mb-3 flex flex-wrap items-end justify-between gap-x-6 gap-y-1">
                <div>
                  <p className="kicker text-brand">{copy.kicker}</p>
                  <h3 className="mt-1 font-display text-xl font-semibold leading-tight tracking-tight sm:text-3xl">
                    {copy.title}
                  </h3>
                </div>
                <p className="hidden max-w-md text-[13px] leading-relaxed text-muted-foreground xl:block">{copy.body}</p>
              </div>
            ) : (
              <div className="mb-3 lg:hidden">
                <p className="kicker text-brand">{copy.kicker}</p>
                <h3 className="mt-1 font-display text-lg font-semibold leading-tight tracking-tight sm:text-2xl">{copy.title}</h3>
              </div>
            )}

            <div className={cn("grid min-h-0 flex-1 gap-6", !isFork && "lg:grid-cols-12 lg:gap-10")}>
              {!isFork && (
                <div className="hidden flex-col justify-center lg:col-span-5 lg:flex">
                  <p className="kicker text-brand">{copy.kicker}</p>
                  <h3 className="mt-3 font-display text-[clamp(1.6rem,2.6vw,2.4rem)] font-semibold leading-[1.08] tracking-[-0.03em]">
                    {copy.title}
                  </h3>
                  <p className="mt-4 max-w-md text-[15px] leading-relaxed text-muted-foreground">{copy.body}</p>
                </div>
              )}
              <div className={cn("flex min-h-0 flex-col", !isFork ? "justify-center lg:col-span-7" : "")}>
                <Scene stage={shownStage.id} t={sceneT} />
              </div>
            </div>

            <p className="mt-2 hidden text-center font-mono text-[10.5px] text-zinc-600 sm:block">
              Illustrative walkthrough of one made-up package, not a real scan · keep scrolling
            </p>
          </div>
        </div>
      </section>

      <SandboxLimits />
    </div>
  );
}

function Scene({ stage, t }: { stage: StageId; t: number }) {
  switch (stage) {
    case "fetch":
      return <FetchScene t={t} />;
    case "intel":
      return <IntelScene t={t} />;
    case "info":
      return <InfoScene t={t} />;
    case "fork":
      return <ForkScene t={t} />;
    case "ai":
      return <AiScene t={t} />;
    case "verdict":
      return <VerdictScene t={t} />;
  }
}

function Glow({ stage, t }: { stage: StageId; t: number }) {
  const red = stage === "verdict" || (stage === "fork" && t > 0.38);
  const amber = stage === "info";
  const layer = (color: string, on: boolean) => (
    <div
      aria-hidden
      className={cn("pointer-events-none absolute inset-0 transition-opacity duration-700", on ? "opacity-100" : "opacity-0")}
      style={{
        background: `radial-gradient(55% 45% at 50% 0%, color-mix(in oklch, ${color}, transparent 80%), transparent 72%)`,
      }}
    />
  );
  return (
    <>
      {layer("var(--brand)", !red && !amber)}
      {layer("var(--suspicious)", amber && !red)}
      {layer("var(--malicious)", red)}
      <div className="bg-grid pointer-events-none absolute inset-0 opacity-40 [mask-image:radial-gradient(ellipse_70%_60%_at_50%_30%,black,transparent)]" />
    </>
  );
}

function Rail({
  stage,
  index,
  t,
  onJump,
}: {
  stage: StageId;
  index: number;
  t: number;
  onJump: (s: StageId) => void;
}) {
  const nodeIdx = RAIL.map((r, i) => (r.stage === stage ? i : -1)).filter((i) => i >= 0);
  const first = nodeIdx[0];
  const last = nodeIdx[nodeIdx.length - 1];
  const frac = clamp01((first + (last - first + 0.9) * t) / (RAIL.length - 1));
  return (
    <nav aria-label="Steps" className="relative mx-auto w-full max-w-6xl px-6 pb-1">
      <ol className="relative flex items-start justify-between">
        <span aria-hidden className="absolute left-3 right-3 top-3 h-px bg-white/10" />
        <span
          aria-hidden
          className="absolute left-3 top-3 h-px bg-gradient-to-r from-brand/40 to-brand shadow-[0_0_10px_var(--brand)]"
          style={{ width: `calc((100% - 1.5rem) * ${frac})` }}
        />
        {RAIL.map((r) => {
          const stIndex = STAGES.findIndex((s) => s.id === r.stage);
          const active = stIndex === index;
          const done = stIndex < index;
          return (
            <li key={r.n} className="relative z-10 flex w-6 flex-col items-center">
              <button
                type="button"
                onClick={() => onJump(r.stage)}
                aria-current={active ? "step" : undefined}
                aria-label={`Step ${r.n}: ${r.label}`}
                className={cn(
                  "flex size-6 items-center justify-center rounded-full border font-mono text-[10px] font-semibold transition-all duration-300",
                  active && "scale-125 border-brand bg-brand text-brand-foreground shadow-[0_0_18px_var(--brand)]",
                  done && "border-brand/60 bg-brand/20 text-brand",
                  !active && !done && "border-white/15 bg-black text-zinc-500"
                )}
              >
                {r.n}
              </button>
              <span
                className={cn(
                  "mt-1.5 hidden whitespace-nowrap text-[11px] transition-colors sm:block",
                  active ? "text-foreground" : "text-zinc-600"
                )}
              >
                {r.label}
                {r.lane === "sandbox" && !SANDBOX_LIVE && <span className="ml-1 text-suspicious">·soon</span>}
              </span>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

function ThreeWays() {
  const items = [
    { icon: Eye, name: "Read", line: "Static scan parses the code as text. Never runs it." },
    { icon: Play, name: "Run", line: "A locked sandbox executes it and records what it does.", soon: !SANDBOX_LIVE },
    { icon: BrainCircuit, name: "Reason", line: "An AI weighs both and explains the call." },
  ];
  return (
    <ul className="mx-auto mt-12 grid max-w-4xl gap-3 px-4 sm:grid-cols-3 sm:px-6">
      {items.map((i) => (
        <li key={i.name} className="rounded-xl border border-white/10 bg-white/[0.03] p-4">
          <div className="flex items-center gap-2">
            <span className="flex size-7 items-center justify-center rounded-md bg-brand/10 text-brand">
              <i.icon className="size-4" />
            </span>
            <span className="font-display text-base font-semibold">{i.name}</span>
            {i.soon && (
              <span className="ml-auto rounded-full border border-suspicious/40 bg-suspicious/10 px-2 py-0.5 font-mono text-[10px] text-suspicious">
                In development
              </span>
            )}
          </div>
          <p className="mt-2 text-[13px] leading-relaxed text-muted-foreground">{i.line}</p>
        </li>
      ))}
    </ul>
  );
}

function SandboxLimits() {
  return (
    <div className="mx-auto max-w-4xl px-4 pb-24 sm:px-6">
      <div className="rounded-xl border border-white/10 bg-white/[0.02] p-5">
        <p className="text-sm font-semibold text-foreground">What the sandbox can&apos;t see</p>
        <ul className="mt-2 grid gap-x-8 gap-y-1 text-[13px] text-muted-foreground sm:grid-cols-2">
          {SANDBOX_LIMITS.map((l) => (
            <li key={l} className="flex gap-2">
              <span aria-hidden className="mt-2 size-1 shrink-0 rounded-full bg-zinc-600" />
              {l}
            </li>
          ))}
        </ul>
        <p className="mt-3 text-[13px] text-zinc-400">Static analysis and AI review still cover these.</p>
      </div>
    </div>
  );
}

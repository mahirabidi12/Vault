"use client";

import * as React from "react";
import {
  ArrowRight,
  Ban,
  Box,
  Check,
  Cloud,
  Database,
  Download,
  FileCode2,
  FileKey2,
  Fingerprint,
  ListChecks,
  Package,
  Radar,
  ScanLine,
  ShieldCheck,
  Sparkles,
  Timer,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { VerdictRecord } from "@/lib/types/domain";

type StageKey = "fetch" | "intel" | "info" | "static" | "sandbox" | "ai" | "verdict";

type Stage = {
  key: StageKey;
  label: string;
  short: string;
  doing: string;
  seconds: number;
  icon: typeof Download;
  lines: string[];
};

// Typical durations. The API only says pending / scanning / done, so the step shown is an estimate.
const STAGES: Stage[] = [
  {
    key: "fetch",
    label: "Fetch and verify",
    short: "Fetch",
    doing: "Downloading the exact package from npm and checking it against the registry's own hash.",
    seconds: 3,
    icon: Download,
    lines: ["Resolving the exact version", "Downloading the tarball", "Comparing the integrity hash", "Unpacking safely: no path tricks, no links"],
  },
  {
    key: "intel",
    label: "Threat intelligence",
    short: "Intel",
    doing: "Asking two public malware databases whether they already know this package.",
    seconds: 3,
    icon: Radar,
    lines: ["Querying OSV.dev", "Querying SafeDep", "A known-malware match would end the scan here"],
  },
  {
    key: "info",
    label: "Package info",
    short: "Info",
    doing: "Checking install scripts, publisher, age, name lookalikes and registry metadata.",
    seconds: 2,
    icon: ListChecks,
    lines: ["Looking for install scripts", "Checking who published it and when", "Comparing the name with popular packages"],
  },
  {
    key: "static",
    label: "Static code scan",
    short: "Static",
    doing: "Reading the code as text, never running it, looking for risky patterns.",
    seconds: 5,
    icon: FileCode2,
    lines: ["Parsing files into syntax trees", "Looking for network calls and shell commands", "Matching known-bad byte patterns", "Combining findings: secrets plus network is worse than either"],
  },
  {
    key: "sandbox",
    label: "Sandbox run",
    short: "Sandbox",
    doing: "Installing and running it inside a locked box with no internet, and recording what it does.",
    seconds: 14,
    icon: Box,
    lines: ["Run A: install with scripts on", "Run A: load the main file", "Run B: pretend to be CI, clock moved forward", "Watching DNS, connections, processes and files"],
  },
  {
    key: "ai",
    label: "AI review",
    short: "AI",
    doing: "An AI reads the code together with the sandbox recording and explains what it finds.",
    seconds: 14,
    icon: Sparkles,
    lines: ["Reading the flagged files", "Searching the code for suspicious patterns", "Weighing the static findings and the recording", "Writing the explanation"],
  },
  {
    key: "verdict",
    label: "Verdict",
    short: "Verdict",
    doing: "Combining every layer into one verdict, with who decided it and why.",
    seconds: 2,
    icon: ShieldCheck,
    lines: ["Applying the scoring rules", "Saving the report so the next lookup is instant"],
  },
];

const BOUNDS = (() => {
  let acc = 0;
  return STAGES.map((s) => {
    const start = acc;
    acc += s.seconds;
    return { start, end: acc };
  });
})();
const TOTAL = BOUNDS[BOUNDS.length - 1].end;

function useElapsed(record: VerdictRecord) {
  const [start] = React.useState(() => {
    const mounted = Date.now();
    const offset = Math.min(60_000, Math.max(0, mounted - new Date(record.requestedAt).getTime()));
    return mounted - offset;
  });
  const [now, setNow] = React.useState(start);
  React.useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 200);
    return () => clearInterval(id);
  }, []);
  return record.status === "PENDING" ? 0 : Math.max(0, (now - start) / 1000);
}

export function LiveScanProgress({ record }: { record: VerdictRecord }) {
  const elapsed = useElapsed(record);
  const queued = record.status === "PENDING";

  let index = BOUNDS.findIndex((b) => elapsed < b.end);
  const overrun = index === -1;
  if (overrun) index = STAGES.length - 1;
  const stage = STAGES[index];
  const local = overrun ? (elapsed * 0.5) % 1 : (elapsed - BOUNDS[index].start) / stage.seconds;
  const p = Math.min(1, Math.max(0, local));
  const slow = elapsed > TOTAL + 45;

  const mm = Math.floor(elapsed / 60);
  const ss = Math.floor(elapsed % 60);

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-5 px-4 pb-16 pt-6 sm:px-6 sm:pt-8">
      {/* header */}
      <header className="relative isolate flex flex-col gap-4 overflow-hidden rounded-3xl border border-white/10 bg-white/[0.03] p-5 sm:p-6">
        <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
          <div className="blob-drift absolute -left-[10%] -top-[50%] size-[70%] rounded-full bg-brand/15 blur-3xl" />
          <div className="bg-grid absolute inset-0 opacity-40 [mask-image:radial-gradient(ellipse_70%_80%_at_30%_30%,black,transparent)]" />
          <div className="sweep-x absolute inset-y-0 left-0 w-1/4 bg-gradient-to-r from-transparent via-white/10 to-transparent [animation-iteration-count:infinite]" />
        </div>

        <div className="flex flex-wrap items-center justify-between gap-6">
          <div className="flex min-w-0 items-center gap-5">
            <span className="relative flex size-14 shrink-0 items-center justify-center rounded-2xl border border-white/10 bg-black/40">
              <span aria-hidden className="ping-ring absolute inset-0 rounded-2xl border border-brand/50" />
              <ScanLine className="size-7 text-brand" />
            </span>
            <div className="min-w-0">
              <p className="kicker flex items-center gap-2 text-brand">
                <span className="relative flex size-2">
                  <span className="ping-ring absolute inline-flex size-full rounded-full bg-brand" />
                  <span className="relative inline-flex size-2 rounded-full bg-brand" />
                </span>
                {queued ? "Waiting for a worker" : "Scanning now"}
              </p>
              <h1 className="mt-1 flex flex-wrap items-baseline gap-x-3 font-display text-[clamp(1.6rem,3.6vw,2.4rem)] font-semibold leading-[1.05] tracking-[-0.04em]">
                <span className="break-all">{record.package.name}</span>
                <span className="rounded-lg border border-white/10 bg-white/5 px-2.5 py-1 font-mono text-base font-normal tracking-normal text-muted-foreground">
                  v{record.package.version}
                </span>
              </h1>
            </div>
          </div>

          <div className="flex items-center gap-3 rounded-2xl border border-white/10 bg-black/40 px-4 py-2.5">
            <Timer className="size-5 text-muted-foreground" />
            <div>
              <p className="font-mono text-2xl font-semibold tabular-nums leading-none">
                {mm}:{String(ss).padStart(2, "0")}
              </p>
              <p className="mt-1 text-xs text-muted-foreground">usually 20 to 60 seconds</p>
            </div>
          </div>
        </div>

        <p className="max-w-3xl text-sm leading-relaxed text-muted-foreground">
          First scan of this exact version. The result opens here by itself, and it is instant for everyone after this.
        </p>

        {/* segmented overall progress */}
        <div className="flex gap-1.5" aria-hidden>
          {STAGES.map((s, i) => {
            const fill = i < index ? 1 : i === index ? (queued ? 0 : overrun ? 1 : p) : 0;
            return (
              <div key={s.key} className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/10">
                <div className="h-full rounded-full bg-gradient-to-r from-brand/70 to-white transition-[width] duration-200" style={{ width: `${fill * 100}%` }} />
              </div>
            );
          })}
        </div>
      </header>

      {/* stage rail */}
      <Rail index={index} queued={queued} />

      {/* what is happening now */}
      <section key={stage.key} className="rise-in grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.5fr)] lg:items-stretch">
        <div className="flex flex-col gap-5 rounded-3xl border border-white/10 bg-white/[0.03] p-6 sm:p-8">
          <div className="flex items-center gap-3">
            <span className="relative flex size-12 items-center justify-center rounded-2xl border border-brand/40 bg-brand/10 text-brand">
              <span aria-hidden className="ping-ring absolute inset-0 rounded-2xl border border-brand/40" />
              <stage.icon className="size-6" />
            </span>
            <div>
              <p className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                Step {index + 1} of {STAGES.length} · about {stage.seconds} s
              </p>
              <h2 className="font-display text-2xl font-semibold tracking-tight">{stage.label}</h2>
            </div>
          </div>
          <p className="text-[15px] leading-relaxed text-foreground/85">{stage.doing}</p>

          <ul className="flex flex-col gap-2">
            {stage.lines.map((line, i) => {
              const at = (i + 0.5) / stage.lines.length;
              const done = p > at + 0.12 && !queued;
              const active = !done && p >= at - 0.2 && !queued;
              return (
                <li
                  key={line}
                  className={cn(
                    "flex items-center gap-3 rounded-xl border px-3.5 py-2.5 text-sm transition-all duration-500",
                    active && "border-brand/40 bg-brand/[0.08] text-foreground",
                    done && "border-white/10 bg-white/[0.02] text-muted-foreground",
                    !active && !done && "border-transparent text-muted-foreground/50"
                  )}
                >
                  {done ? (
                    <Check className="size-4 shrink-0 text-safe" />
                  ) : active ? (
                    <span className="size-4 shrink-0 animate-spin rounded-full border-2 border-brand/30 border-t-brand" />
                  ) : (
                    <span className="size-4 shrink-0 rounded-full border border-white/15" />
                  )}
                  {line}
                </li>
              );
            })}
          </ul>

          {slow && (
            <p className="rounded-xl border border-suspicious/30 bg-suspicious/[0.07] px-4 py-3 text-sm text-foreground/85">
              This one is taking longer than usual. Big packages, and the AI and sandbox steps, can take a couple of minutes. Nothing is stuck; the page updates when it is done.
            </p>
          )}
        </div>

        <div className="min-h-[22rem]">
          <Visual stage={stage.key} p={queued ? 0 : p} name={record.package.name} version={record.package.version} />
        </div>
      </section>

      <p className="text-center text-xs text-muted-foreground">
        The server tells us when a scan is done, not which step it is on, so the step shown here is an estimate from typical timings. Real findings, network activity and files appear in the report the moment it is ready.
      </p>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Rail
// ---------------------------------------------------------------------------
function Rail({ index, queued }: { index: number; queued: boolean }) {
  return (
    <nav aria-label="Scan steps" className="rounded-3xl border border-white/10 bg-white/[0.02] p-3 sm:p-4">
      <ol className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:grid-cols-7">
        {STAGES.map((s, i) => {
          const state = queued ? "pending" : i < index ? "done" : i === index ? "active" : "pending";
          return (
            <li
              key={s.key}
              aria-current={state === "active" ? "step" : undefined}
              className={cn(
                "relative flex flex-col items-center gap-1.5 rounded-2xl border px-2 py-3 text-center transition-all duration-500",
                state === "active" && "border-brand/60 bg-brand/[0.09] shadow-[0_0_30px_-8px_var(--brand)]",
                state === "done" && "border-safe/30 bg-safe/[0.05]",
                state === "pending" && "border-white/10 opacity-60"
              )}
            >
              <span
                className={cn(
                  "relative flex size-9 items-center justify-center rounded-xl border transition-colors",
                  state === "active" && "border-brand/60 bg-brand/15 text-brand",
                  state === "done" && "border-safe/40 bg-safe/10 text-safe",
                  state === "pending" && "border-white/15 bg-white/5 text-muted-foreground"
                )}
              >
                {state === "done" ? <Check className="size-4" /> : <s.icon className="size-4" />}
                {state === "active" && <span aria-hidden className="ping-ring absolute inset-0 rounded-xl border border-brand/50" />}
              </span>
              <span className={cn("text-[13px] font-semibold leading-tight", state === "active" ? "text-foreground" : state === "done" ? "text-safe" : "text-muted-foreground")}>
                {s.short}
              </span>
              <span className="text-[11px] text-muted-foreground">
                {state === "done" ? "done" : state === "active" ? "running" : "waiting"}
              </span>
              {i < STAGES.length - 1 && (
                <ArrowRight aria-hidden className="absolute -right-2.5 top-1/2 z-10 hidden size-4 -translate-y-1/2 text-white/25 lg:block" />
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

// ---------------------------------------------------------------------------
// Visuals: one per stage, driven by p (0..1 through the stage)
// ---------------------------------------------------------------------------
function Panel({ title, children, className }: { title: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={cn("relative flex h-full min-h-[22rem] flex-col overflow-hidden rounded-3xl border border-white/12 bg-[#06070b]", className)}>
      <div className="flex items-center gap-1.5 border-b border-white/10 bg-white/[0.03] px-4 py-2.5">
        <span className="size-2.5 rounded-full bg-[#ff5f56]" />
        <span className="size-2.5 rounded-full bg-[#ffbd2e]" />
        <span className="size-2.5 rounded-full bg-[#27c93f]" />
        <span className="ml-2 font-mono text-[11px] text-zinc-500">{title}</span>
        <span className="ml-auto rounded-full border border-white/15 px-2 py-0.5 font-mono text-[10px] text-zinc-400">estimated view</span>
      </div>
      <div className="relative flex min-h-0 flex-1 flex-col p-5 sm:p-7">{children}</div>
    </div>
  );
}

function Visual({ stage, p, name, version }: { stage: StageKey; p: number; name: string; version: string }) {
  switch (stage) {
    case "fetch":
      return <FetchViz p={p} name={name} version={version} />;
    case "intel":
      return <IntelViz p={p} />;
    case "info":
      return <InfoViz p={p} />;
    case "static":
      return <StaticViz p={p} />;
    case "sandbox":
      return <SandboxViz p={p} />;
    case "ai":
      return <AiViz p={p} />;
    case "verdict":
      return <VerdictViz p={p} />;
  }
}

const between = (t: number, a: number, b: number) => Math.min(1, Math.max(0, (t - a) / (b - a)));

function FetchViz({ p, name, version }: { p: number; name: string; version: string }) {
  const travel = between(p, 0, 0.55);
  const hash = between(p, 0.5, 0.95);
  const bits = "sha512-".concat("7Xk2Qp9dLm4tRb0vHn3eYw1aZs8cUj6O");
  const n = Math.floor(bits.length * hash);
  return (
    <Panel title="fetch · registry.npmjs.org">
      <div className="flex items-center justify-between gap-3">
        <Node icon={Database} label="npm registry" sub="published tarball" />
        <div className="relative h-px flex-1 border-t border-dashed border-white/20">
          <span
            className="absolute -top-5 flex items-center gap-1.5 rounded-md border border-brand/50 bg-brand/15 px-2 py-1 font-mono text-[10px] text-brand shadow-[0_0_20px_-4px_var(--brand)]"
            style={{ left: `${travel * 82}%` }}
          >
            <Package className="size-3" />
            {name.length > 14 ? `${name.slice(0, 12)}…` : name}-{version}.tgz
          </span>
        </div>
        <Node icon={Cloud} label="PkgGuard" sub={travel >= 1 ? "received" : "waiting"} active={travel >= 1} />
      </div>
      <div className="mt-auto flex flex-col gap-2 pt-8">
        <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">Integrity check</p>
        <div className="rounded-xl border border-white/10 bg-black/40 p-3 font-mono text-xs">
          <p className="break-all text-zinc-500">registry <span className="text-zinc-300">{bits}</span></p>
          <p className="break-all text-zinc-500">
            computed{" "}
            <span className={hash >= 1 ? "text-safe" : "text-brand"}>
              {bits.slice(0, n)}
              <span className="text-zinc-700">{bits.slice(n).replace(/./g, "·")}</span>
            </span>
          </p>
        </div>
        <p className={cn("flex items-center gap-1.5 font-mono text-[11px] transition-opacity", hash >= 1 ? "text-safe opacity-100" : "opacity-0")}>
          <Fingerprint className="size-3.5" /> Hashes match
        </p>
      </div>
    </Panel>
  );
}

function IntelViz({ p }: { p: number }) {
  const rows = [
    { name: "OSV.dev", sub: "open malware advisories", from: 0, to: 0.6 },
    { name: "SafeDep", sub: "community malware feed", from: 0.25, to: 0.9 },
  ];
  return (
    <Panel title="threat intelligence">
      <div className="grid gap-4 sm:grid-cols-2">
        {rows.map((r) => {
          const v = between(p, r.from, r.to);
          return (
            <div key={r.name} className="relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] p-5">
              <div className="flex items-center gap-2">
                <Database className={cn("size-4", v > 0 ? "text-brand" : "text-zinc-600")} />
                <span className="font-display font-semibold">{r.name}</span>
              </div>
              <p className="mt-0.5 text-xs text-zinc-500">{r.sub}</p>
              <div className="mt-5 h-2 overflow-hidden rounded-full bg-white/10">
                <div className="h-full rounded-full bg-brand transition-[width] duration-200" style={{ width: `${v * 100}%` }} />
              </div>
              <p className="mt-3 font-mono text-xs text-zinc-400">{v >= 1 ? "answer received" : v > 0 ? "looking it up…" : "queued"}</p>
            </div>
          );
        })}
      </div>
      <p className="mt-auto rounded-xl border border-white/10 bg-white/[0.03] p-4 text-sm text-zinc-300">
        A known-malware match ends the scan here, and nothing later can override it. If neither database knows the package, the deeper checks decide.
      </p>
    </Panel>
  );
}

function InfoViz({ p }: { p: number }) {
  const checks = ["Install scripts", "Published when", "Publisher history", "Repository linked", "Trusted publishing", "Name lookalikes", "Version jump", "Tarball vs registry"];
  return (
    <Panel title="package info">
      <div className="grid grid-cols-2 gap-3">
        {checks.map((c, i) => {
          const done = p > (i + 0.6) / (checks.length + 0.5);
          const active = !done && p > i / (checks.length + 0.5);
          return (
            <div
              key={c}
              className={cn(
                "flex items-center gap-3 rounded-xl border px-3.5 py-3 text-sm transition-all duration-400",
                done ? "border-white/15 bg-white/[0.05]" : active ? "border-brand/50 bg-brand/[0.08]" : "border-white/8 opacity-50"
              )}
            >
              <span className="flex size-6 items-center justify-center">
                {done ? <Check className="size-4 text-safe" /> : active ? <span className="size-4 animate-spin rounded-full border-2 border-brand/30 border-t-brand" /> : <span className="size-2 rounded-full bg-white/20" />}
              </span>
              {c}
            </div>
          );
        })}
      </div>
    </Panel>
  );
}

function StaticViz({ p }: { p: number }) {
  const widths = [72, 48, 88, 60, 34, 80, 52, 66, 40, 76, 58, 90];
  const beam = p * 100;
  return (
    <Panel title="static scan · read as text, never run">
      <div className="relative flex-1 overflow-hidden rounded-xl border border-white/10 bg-black/40 p-4">
        <div className="flex flex-col gap-2.5">
          {widths.map((w, i) => {
            const scanned = beam > (i / widths.length) * 100;
            const flag = i === 3 || i === 8;
            return (
              <div key={i} className="flex items-center gap-3">
                <span className="w-5 text-right font-mono text-[10px] text-zinc-600">{i + 1}</span>
                <span
                  className={cn("h-2.5 rounded-full transition-colors duration-300", scanned ? (flag ? "bg-suspicious/70" : "bg-white/30") : "bg-white/8")}
                  style={{ width: `${w}%` }}
                />
              </div>
            );
          })}
        </div>
        <span aria-hidden className="pointer-events-none absolute inset-x-0 h-14 bg-gradient-to-b from-transparent via-brand/25 to-transparent" style={{ top: `calc(${beam}% - 28px)` }} />
      </div>
      <div className="mt-4 flex flex-wrap gap-2 font-mono text-[11px] text-zinc-400">
        {["network calls", "shell commands", "eval", "secret reads", "hidden payloads"].map((t, i) => (
          <span key={t} className={cn("rounded-full border px-2.5 py-1 transition-colors", p > (i + 1) / 6 ? "border-brand/40 bg-brand/10 text-brand" : "border-white/10")}>
            {t}
          </span>
        ))}
      </div>
    </Panel>
  );
}

function SandboxViz({ p }: { p: number }) {
  const phases = [
    { label: "install (scripts on)", at: 0.05 },
    { label: "load the main file", at: 0.3 },
    { label: "run its command-line tools", at: 0.45 },
  ];
  const decoys = ["fake ~/.npmrc", "fake ~/.ssh/id_rsa", "fake AWS keys", "fake browser data"];
  const a = between(p, 0, 0.75);
  const b = between(p, 0.1, 0.95);
  return (
    <div className="relative flex h-full min-h-[22rem] flex-col overflow-hidden rounded-3xl border border-white/15 bg-[#05060a] shadow-[0_0_80px_-20px_var(--brand)]">
      <svg aria-hidden className="pointer-events-none absolute inset-0 size-full">
        <rect x="1" y="1" rx="24" fill="none" strokeWidth="1.5" className="flow stroke-brand/50" style={{ width: "calc(100% - 2px)", height: "calc(100% - 2px)" }} />
      </svg>
      <div className="relative flex flex-wrap items-center gap-3 border-b border-white/10 bg-white/[0.03] px-5 py-3">
        <span className="flex items-center gap-2 font-display text-sm font-semibold">
          <Box className="size-4 text-brand" /> PkgGuard sandbox
        </span>
        <span className="hidden font-mono text-[11px] text-zinc-500 sm:inline">isolated microVM · no internet · unprivileged user</span>
        <span className="ml-auto inline-flex items-center gap-1.5 rounded-full border border-brand/40 bg-brand/10 px-2.5 py-0.5 font-mono text-[10px] text-brand">
          <span className="relative flex size-1.5">
            <span className="ping-ring absolute inline-flex size-full rounded-full bg-brand" />
            <span className="relative inline-flex size-1.5 rounded-full bg-brand" />
          </span>
          analysing
        </span>
      </div>

      <div className="relative grid flex-1 gap-0 md:grid-cols-[1fr_1.4fr_1fr]">
        <div className="hidden flex-col gap-2 border-r border-white/10 p-4 md:flex">
          <p className="flex items-center gap-1.5 font-mono text-[10.5px] uppercase tracking-wider text-zinc-500">
            <FileKey2 className="size-3" /> Planted decoys
          </p>
          {decoys.map((d, i) => (
            <span key={d} className={cn("rounded-lg border px-2.5 py-1.5 font-mono text-[11px] transition-colors", p > 0.2 + i * 0.12 ? "border-suspicious/40 bg-suspicious/[0.07] text-suspicious/90" : "border-white/10 text-zinc-500")}>
              {d}
            </span>
          ))}
          <p className="mt-auto text-[11px] leading-snug text-zinc-500">If a fake value ever leaves the box, that is proof of theft.</p>
        </div>

        <div className="flex flex-col gap-2 p-4 md:border-r md:border-white/10">
          <p className="font-mono text-[10.5px] uppercase tracking-wider text-zinc-500">Doing now</p>
          {phases.map((ph) => {
            const done = p > ph.at + 0.2;
            const active = !done && p >= ph.at;
            return (
              <div key={ph.label} className={cn("flex items-center gap-3 rounded-xl border px-3 py-2.5 text-sm transition-all duration-500", active ? "border-brand/50 bg-brand/[0.09]" : done ? "border-white/10 bg-white/[0.03] text-zinc-400" : "border-white/8 text-zinc-600")}>
                {done ? <Check className="size-4 text-safe" /> : active ? <span className="size-4 animate-spin rounded-full border-2 border-brand/30 border-t-brand" /> : <span className="size-4 rounded-full border border-white/15" />}
                {ph.label}
              </div>
            );
          })}
          <div className="mt-auto flex flex-col gap-2 pt-3">
            <RunBar label="Run A · normal" v={a} />
            <RunBar label="Run B · CI=true, clock +60 days" v={b} />
          </div>
        </div>

        <div className="flex flex-col gap-3 p-4">
          <p className="font-mono text-[10.5px] uppercase tracking-wider text-zinc-500">Fake internet</p>
          <div className="flex items-center gap-2">
            <span className="flex size-9 items-center justify-center rounded-lg border border-white/10 bg-white/[0.03] text-zinc-500">
              <Cloud className="size-4" />
            </span>
            <span className="flex h-px flex-1 items-center border-t border-dashed border-white/20">
              <span className="mx-auto -mt-px flex size-5 items-center justify-center rounded-full border border-malicious/50 bg-black text-malicious">
                <Ban className="size-3" />
              </span>
            </span>
          </div>
          <p className="rounded-lg border border-brand/30 bg-brand/5 px-3 py-2 text-[11px] leading-snug text-zinc-300">
            <span className="font-semibold text-brand">Sinkhole</span> answers every DNS name and web request and logs it. Nothing real leaves the box.
          </p>
          <p className="mt-auto text-[11px] leading-snug text-zinc-500">This view shows the steps, not the package&apos;s real events. Those appear in the report.</p>
        </div>
      </div>
    </div>
  );
}

function RunBar({ label, v }: { label: string; v: number }) {
  return (
    <div className="flex items-center gap-3 font-mono text-[10.5px] text-zinc-500">
      <span className="w-40 shrink-0 truncate">{label}</span>
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/10">
        <div className="h-full rounded-full bg-gradient-to-r from-brand/60 to-white transition-[width] duration-200" style={{ width: `${v * 100}%` }} />
      </div>
    </div>
  );
}

function AiViz({ p }: { p: number }) {
  const inputs = ["Static findings", "Sandbox recording", "Package source"];
  const tools = ["list_files", "read_file install script", "search  network patterns", "read_file entry point", "search  env access"];
  return (
    <Panel title="AI review">
      <div className="flex flex-wrap gap-2">
        {inputs.map((i, k) => (
          <span key={i} className={cn("flex items-center gap-2 rounded-lg border px-3 py-1.5 font-mono text-xs transition-all duration-500", p > k * 0.1 ? "border-brand/40 bg-brand/10 text-foreground" : "border-white/10 text-zinc-600")}>
            <Check className={cn("size-3", p > k * 0.1 ? "text-brand" : "text-transparent")} />
            {i}
          </span>
        ))}
      </div>
      <div className="mt-5 flex-1 rounded-2xl border border-white/10 bg-black/40 p-4 font-mono text-xs">
        <p className="mb-3 text-[10.5px] uppercase tracking-wider text-brand">Tool calls</p>
        <ul className="flex flex-col gap-2">
          {tools.map((t, i) => {
            const shown = p > 0.15 + i * 0.14;
            return (
              <li key={t} className={cn("flex items-center gap-2 transition-all duration-500", shown ? "translate-x-0 text-zinc-200 opacity-100" : "-translate-x-2 opacity-0")}>
                <ArrowRight className="size-3 text-brand" /> {t}
              </li>
            );
          })}
        </ul>
        <p className="mt-5 flex items-center gap-2 text-zinc-500">
          thinking
          <span className="inline-flex gap-1">
            {[0, 1, 2].map((d) => (
              <span key={d} className="size-1.5 animate-bounce rounded-full bg-brand" style={{ animationDelay: `${d * 150}ms` }} />
            ))}
          </span>
        </p>
      </div>
    </Panel>
  );
}

function VerdictViz({ p }: { p: number }) {
  return (
    <Panel title="verdict">
      <div className="flex flex-1 flex-col items-center justify-center gap-5 text-center">
        <span className="relative flex size-28 items-center justify-center">
          <span aria-hidden className="ping-ring absolute inset-0 rounded-full border border-brand/50" />
          <svg viewBox="0 0 128 128" className="absolute inset-0 size-full -rotate-90" aria-hidden>
            <circle cx="64" cy="64" r="54" fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="6" />
            <circle cx="64" cy="64" r="54" fill="none" stroke="var(--brand)" strokeWidth="6" strokeLinecap="round" strokeDasharray={339} strokeDashoffset={339 * (1 - Math.max(0.1, p))} className="transition-[stroke-dashoffset] duration-300" />
          </svg>
          <ShieldCheck className="size-10 text-brand" />
        </span>
        <p className="max-w-xs text-sm text-zinc-300">Putting every layer together. The report opens here as soon as it is ready.</p>
      </div>
    </Panel>
  );
}

function Node({ icon: Icon, label, sub, active }: { icon: typeof Database; label: string; sub: string; active?: boolean }) {
  return (
    <div className={cn("flex shrink-0 flex-col items-center gap-1.5 rounded-xl border px-4 py-3 text-center transition-colors", active ? "border-brand/50 bg-brand/10" : "border-white/10 bg-white/[0.03]")}>
      <Icon className={cn("size-5", active ? "text-brand" : "text-zinc-400")} />
      <span className="font-mono text-[11px] text-foreground">{label}</span>
      <span className="font-mono text-[10px] text-zinc-500">{sub}</span>
    </div>
  );
}

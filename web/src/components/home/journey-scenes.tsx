"use client";

import * as React from "react";
import {
  AlertTriangle,
  Archive,
  Check,
  Database,
  FileCode2,
  Fingerprint,
  Package,
  ShieldAlert,
  Sparkles,
  X,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { SandboxContainer } from "@/components/home/sandbox-container";
import {
  AI_TEXT,
  DECIDED_BY,
  DEMO,
  INFO_FLAGS,
  STATIC_FILES,
  STATIC_FINDINGS,
  between,
  typed,
} from "@/lib/pipeline-flow";

type SceneProps = { t: number };

/** Small window chrome shared by the calmer scenes. */
function Window({
  title,
  children,
  className,
  tag = "Illustrative example",
}: {
  title: string;
  children: React.ReactNode;
  className?: string;
  tag?: string | null;
}) {
  return (
    <div className={cn("flex min-h-0 flex-col overflow-hidden rounded-2xl border border-white/12 bg-[#07080c]", className)}>
      <div className="flex items-center gap-1.5 border-b border-white/10 bg-white/[0.03] px-4 py-2.5">
        <span className="size-2.5 rounded-full bg-[#ff5f56]" />
        <span className="size-2.5 rounded-full bg-[#ffbd2e]" />
        <span className="size-2.5 rounded-full bg-[#27c93f]" />
        <span className="ml-2 font-mono text-[11px] text-zinc-500">{title}</span>
        {tag && (
          <span className="ml-auto rounded-full border border-white/15 px-2 py-0.5 font-mono text-[10px] text-zinc-400">
            {tag}
          </span>
        )}
      </div>
      <div className="relative flex min-h-0 flex-1 flex-col p-4 sm:p-6">{children}</div>
    </div>
  );
}

function Scanline({ on }: { on: boolean }) {
  if (!on) return null;
  return (
    <span
      aria-hidden
      className="pointer-events-none absolute inset-x-0 top-0 h-16 bg-gradient-to-b from-transparent via-brand/15 to-transparent [animation:scan-sweep_2.4s_linear_infinite] motion-reduce:hidden"
    />
  );
}

// ---------------------------------------------------------------------------
// 1. Fetch & verify
// ---------------------------------------------------------------------------
export function FetchScene({ t }: SceneProps) {
  const travel = between(t, 0.05, 0.4);
  const hash = between(t, 0.45, 0.75);
  const chars = Math.floor(DEMO.integrity.length * hash);
  const checks = [
    { label: "No ../ or absolute paths", at: 0.78 },
    { label: "No symlinks or hardlinks", at: 0.84 },
    { label: `${DEMO.files} files, ${DEMO.sizeKb} KB, under size caps`, at: 0.9 },
  ];
  return (
    <Window title="1 · fetch & verify" className="my-auto">
      <Scanline on={t > 0.4 && t < 0.78} />
      <div className="relative flex items-center justify-between gap-3">
        <Node icon={Database} label="registry.npmjs.org" sub="published tarball" />
        <div className="relative mx-1 h-px flex-1 border-t border-dashed border-white/20 sm:mx-4">
          <span
            className="absolute -top-4 flex items-center gap-1.5 rounded-md border border-brand/50 bg-brand/15 px-2 py-1 font-mono text-[10px] text-brand shadow-[0_0_20px_-4px_var(--brand)]"
            style={{ left: `${travel * 78}%`, opacity: t > 0.04 ? 1 : 0 }}
          >
            <Package className="size-3" />
            .tgz
          </span>
        </div>
        <Node icon={Archive} label="PkgGuard" sub={t > 0.4 ? "received" : "waiting"} active={t > 0.4} />
      </div>

      <div className="mt-8 flex flex-col gap-2">
        <p className="font-mono text-[11px] uppercase tracking-wider text-zinc-500">Integrity hash</p>
        <div className="rounded-lg border border-white/10 bg-black/40 p-3 font-mono text-[11px] leading-relaxed sm:text-xs">
          <p className="break-all text-zinc-500">
            registry <span className="text-zinc-300">{DEMO.integrity}</span>
          </p>
          <p className="break-all text-zinc-500">
            computed{" "}
            <span className={hash >= 1 ? "text-safe" : "text-brand"}>
              {DEMO.integrity.slice(0, chars)}
              <span className="text-zinc-700">{DEMO.integrity.slice(chars).replace(/./g, "·")}</span>
            </span>
          </p>
        </div>
        <p
          className={cn(
            "flex items-center gap-1.5 font-mono text-[11px] transition-opacity",
            hash >= 1 ? "text-safe opacity-100" : "opacity-0"
          )}
        >
          <Fingerprint className="size-3.5" /> Hashes match. This is exactly what npm published.
        </p>
      </div>

      <ul className="mt-auto flex flex-col gap-1.5 pt-6">
        {checks.map((c) => (
          <li
            key={c.label}
            className={cn(
              "flex items-center gap-2 text-[13px] transition-all duration-300",
              t >= c.at ? "translate-x-0 text-foreground opacity-100" : "-translate-x-2 text-zinc-600 opacity-40"
            )}
          >
            <Check className={cn("size-3.5", t >= c.at ? "text-safe" : "text-zinc-700")} />
            {c.label}
          </li>
        ))}
      </ul>
    </Window>
  );
}

function Node({
  icon: Icon,
  label,
  sub,
  active,
}: {
  icon: typeof Database;
  label: string;
  sub: string;
  active?: boolean;
}) {
  return (
    <div
      className={cn(
        "flex shrink-0 flex-col items-center gap-1.5 rounded-xl border px-3 py-3 text-center transition-colors sm:px-5",
        active ? "border-brand/50 bg-brand/10" : "border-white/10 bg-white/[0.03]"
      )}
    >
      <Icon className={cn("size-5", active ? "text-brand" : "text-zinc-400")} />
      <span className="font-mono text-[11px] text-foreground">{label}</span>
      <span className="font-mono text-[10px] text-zinc-500">{sub}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// 2. Threat intel
// ---------------------------------------------------------------------------
export function IntelScene({ t }: SceneProps) {
  const sources = [
    { name: "OSV.dev", sub: "open malware advisories", from: 0.1, to: 0.45 },
    { name: "SafeDep", sub: "community malware feed", from: 0.4, to: 0.75 },
  ];
  return (
    <Window title="2 · threat intel" className="my-auto">
      <div className="grid gap-4 sm:grid-cols-2">
        {sources.map((s) => {
          const p = between(t, s.from, s.to);
          const done = p >= 1;
          return (
            <div key={s.name} className="relative overflow-hidden rounded-xl border border-white/10 bg-white/[0.03] p-4">
              <div className="flex items-center gap-2">
                <Database className={cn("size-4", p > 0 ? "text-brand" : "text-zinc-600")} />
                <span className="font-display text-sm font-semibold">{s.name}</span>
              </div>
              <p className="mt-0.5 text-[11px] text-zinc-500">{s.sub}</p>
              <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-white/10">
                <div className="h-full rounded-full bg-brand transition-[width] duration-150" style={{ width: `${p * 100}%` }} />
              </div>
              <p className="mt-3 h-4 font-mono text-[11px]">
                {p === 0 && <span className="text-zinc-600">queued</span>}
                {p > 0 && !done && (
                  <span className="text-zinc-400">
                    looking up {DEMO.name}@{DEMO.version}…
                  </span>
                )}
                {done && <span className="text-suspicious">no match: unknown here</span>}
              </p>
            </div>
          );
        })}
      </div>

      <div
        className={cn(
          "mt-5 flex flex-col gap-3 transition-all duration-500",
          t > 0.8 ? "translate-y-0 opacity-100" : "translate-y-3 opacity-0"
        )}
      >
        <div className="rounded-xl border border-malicious/30 bg-malicious/5 p-3.5 text-[13px] leading-relaxed text-zinc-300">
          <span className="font-semibold text-malicious">A known-malware match ends the scan here.</span> Nothing later can
          override it.
        </div>
        <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3.5 text-[13px] leading-relaxed text-zinc-300">
          <span className="font-semibold text-foreground">This one is 6 hours old.</span> Brand-new malware is in no database
          yet, so we keep going. That is the gap the next steps are built for.
        </div>
      </div>
    </Window>
  );
}

// ---------------------------------------------------------------------------
// 3. Package info
// ---------------------------------------------------------------------------
export function InfoScene({ t }: SceneProps) {
  const shown = INFO_FLAGS.filter((f) => t >= f.at);
  const warns = shown.filter((f) => f.warn).length;
  return (
    <Window title="3 · package info" className="my-auto">
      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
        {INFO_FLAGS.map((f) => {
          const on = t >= f.at;
          return (
            <div
              key={f.label}
              className={cn(
                "flex items-center gap-3 rounded-xl border px-3.5 py-2.5 transition-all duration-500",
                !on && "border-white/8 bg-white/[0.015] opacity-40",
                on && f.warn && "border-suspicious/40 bg-suspicious/10",
                on && !f.warn && "border-safe/30 bg-safe/5"
              )}
            >
              <span
                className={cn(
                  "flex size-7 shrink-0 items-center justify-center rounded-full border transition-colors",
                  !on && "border-white/10 text-zinc-700",
                  on && f.warn && "border-suspicious/50 text-suspicious",
                  on && !f.warn && "border-safe/40 text-safe"
                )}
              >
                {on ? f.warn ? <AlertTriangle className="size-3.5" /> : <Check className="size-3.5" /> : <span className="size-1.5 rounded-full bg-zinc-700" />}
              </span>
              <span className="min-w-0">
                <span className="block text-[13px] font-medium text-foreground">{f.label}</span>
                <span className="block truncate font-mono text-[11px] text-zinc-500">{on ? f.detail : "checking…"}</span>
              </span>
            </div>
          );
        })}
      </div>
      <p
        className={cn(
          "mt-auto pt-5 text-[13px] leading-relaxed text-zinc-400 transition-opacity duration-500",
          t > 0.92 ? "opacity-100" : "opacity-0"
        )}
      >
        <span className="font-semibold text-suspicious">{warns} flags.</span> Enough to be suspicious, not enough to be sure.
        So we look at the code two ways at once.
      </p>
    </Window>
  );
}

// ---------------------------------------------------------------------------
// 4 + 5. Read it and run it, in parallel
// ---------------------------------------------------------------------------
export function ForkScene({ t }: SceneProps) {
  const staticDone = t >= 0.62;
  return (
    <div className="grid h-full min-h-0 grid-rows-[auto_minmax(0,1fr)] gap-3 lg:grid-cols-12 lg:grid-rows-1 lg:gap-4">
      {/* Lane A: read it */}
      <Window
        title="4 · static scan · reads it"
        tag={null}
        className="max-h-44 lg:col-span-3 lg:max-h-none"
      >
        <Scanline on={!staticDone} />
        <ul className="hidden flex-col gap-1 font-mono text-[10.5px] text-zinc-500 lg:flex">
          {STATIC_FILES.map((f, i) => {
            const on = between(t, 0.04 + i * 0.09, 0.4) > 0 && t < 0.62;
            return (
              <li key={f} className={cn("flex items-center gap-1.5 truncate", on ? "text-zinc-300" : "")}>
                <FileCode2 className="size-3 shrink-0" />
                {f}
              </li>
            );
          })}
        </ul>
        <ul className="mt-3 hidden flex-col gap-1.5 lg:flex">
          {STATIC_FINDINGS.filter((f) => t >= f.at).map((f) => (
            <li
              key={f.rule}
              className={cn(
                "animate-fade-up rounded-md border px-2 py-1.5 text-[10.5px] leading-snug",
                f.sev === "HIGH"
                  ? "border-malicious/40 bg-malicious/10 text-malicious"
                  : "border-suspicious/40 bg-suspicious/10 text-suspicious"
              )}
            >
              <span className="block font-mono text-[9.5px] opacity-70">{f.rule}</span>
              {f.text}
            </li>
          ))}
        </ul>
        <p
          className={cn(
            "mt-auto hidden pt-3 text-[11px] leading-snug transition-opacity lg:block",
            staticDone ? "opacity-100" : "opacity-0"
          )}
        >
          <span className="font-semibold text-suspicious">Static says: suspicious.</span>{" "}
          <span className="text-zinc-500">Text only, never run. It can&apos;t prove intent.</span>
        </p>
        <p className="mt-2 text-[10.5px] text-zinc-600 lg:hidden">
          {STATIC_FINDINGS.filter((f) => t >= f.at).length} of {STATIC_FINDINGS.length} findings · parsed as text, never run
        </p>
      </Window>

      {/* Lane B: run it */}
      <SandboxContainer t={t} className="lg:col-span-9" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// 6. AI review
// ---------------------------------------------------------------------------
export function AiScene({ t }: SceneProps) {
  const text = typed(AI_TEXT, t, 0.3, 0.85);
  const inputs = [
    { label: "Static findings", n: "4 findings", at: 0.05 },
    { label: "Sandbox recording", n: "13 events", at: 0.15 },
    { label: "Package source", n: "5 files", at: 0.25 },
  ];
  return (
    <Window title="6 · AI review" className="my-auto">
      <div className="flex flex-wrap gap-2">
        {inputs.map((i) => (
          <span
            key={i.label}
            className={cn(
              "flex items-center gap-2 rounded-lg border px-2.5 py-1.5 font-mono text-[10.5px] transition-all duration-500",
              t >= i.at ? "border-brand/40 bg-brand/10 text-foreground" : "border-white/10 text-zinc-700 opacity-40"
            )}
          >
            <Check className={cn("size-3", t >= i.at ? "text-brand" : "text-transparent")} />
            {i.label}
            <span className="text-zinc-500">{i.n}</span>
          </span>
        ))}
      </div>

      <div className="relative mt-4 min-h-[13rem] flex-1 overflow-hidden rounded-xl border border-white/10 bg-black/40 p-4">
        <p className="mb-2 flex items-center gap-1.5 font-mono text-[10.5px] uppercase tracking-wider text-brand">
          <Sparkles className="size-3.5" /> Reasoning
        </p>
        <p className="text-[13.5px] leading-relaxed text-zinc-200">
          {text}
          {t < 0.86 && <span className="ml-0.5 inline-block h-[1em] w-1.5 translate-y-0.5 animate-pulse bg-brand" />}
        </p>
      </div>

      <div
        className={cn(
          "mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 rounded-xl border border-malicious/40 bg-malicious/10 px-4 py-3 transition-all duration-500",
          t > 0.9 ? "translate-y-0 opacity-100" : "translate-y-2 opacity-0"
        )}
      >
        <span className="flex items-center gap-1.5 font-display text-sm font-semibold text-malicious">
          <ShieldAlert className="size-4" /> Malicious
        </span>
        <span className="font-mono text-[11px] text-zinc-400">confidence: high</span>
        <span className="font-mono text-[11px] text-zinc-500">AI can raise or clear alarms, but cannot clear sandbox proof</span>
      </div>
    </Window>
  );
}

// ---------------------------------------------------------------------------
// 7. Verdict
// ---------------------------------------------------------------------------
export function VerdictScene({ t }: SceneProps) {
  const stamp = t > 0.15;
  const evidence = [
    { text: "Our fake npm token appeared in an outgoing request", rule: "sandbox.canary_exfil", at: 0.35 },
    { text: "Wrote a line into ~/.bashrc", rule: "sandbox.persistence", at: 0.5 },
    { text: "Second host contacted only when CI=true", rule: "sandbox.conditional_behavior", at: 0.65 },
  ];
  return (
    <Window title="7 · verdict" className="my-auto">
      <div className="flex flex-wrap items-center gap-4">
        <div
          className={cn(
            "flex items-center gap-3 rounded-2xl border-2 border-malicious/60 bg-malicious/10 px-5 py-3 transition-all duration-500",
            stamp ? "scale-100 opacity-100 shadow-[0_0_50px_-8px_var(--malicious)]" : "scale-125 opacity-0"
          )}
        >
          <ShieldAlert className="size-7 text-malicious" />
          <div>
            <p className="font-display text-2xl font-semibold leading-none tracking-tight text-malicious">Malicious</p>
            <p className="mt-1 font-mono text-[11px] text-zinc-400">
              {DEMO.name}@{DEMO.version} · confidence high
            </p>
          </div>
        </div>
        <p className="min-w-[14rem] flex-1 text-[13px] leading-relaxed text-zinc-400">
          Decided by <span className="font-semibold text-foreground">sandbox proof</span>. Every line below links back to the
          rule, log line or code that caused it.
        </p>
      </div>

      <ul className="mt-5 flex flex-col gap-2">
        {evidence.map((e) => (
          <li
            key={e.rule}
            className={cn(
              "flex flex-wrap items-center gap-x-3 gap-y-0.5 rounded-lg border border-white/10 bg-white/[0.03] px-3.5 py-2.5 transition-all duration-500",
              t >= e.at ? "translate-y-0 opacity-100" : "translate-y-2 opacity-0"
            )}
          >
            <X className="size-3.5 shrink-0 text-malicious" />
            <span className="text-[13px] text-foreground">{e.text}</span>
            <span className="ml-auto font-mono text-[10.5px] text-zinc-500">{e.rule}</span>
          </li>
        ))}
      </ul>

      <div
        className={cn(
          "mt-auto grid grid-cols-2 gap-2 pt-5 transition-opacity duration-500 sm:grid-cols-4",
          t > 0.75 ? "opacity-100" : "opacity-0"
        )}
      >
        {DECIDED_BY.map((d) => {
          const hot = d.id === "sandbox";
          return (
            <div
              key={d.id}
              className={cn(
                "rounded-lg border px-2.5 py-2 text-[11px] leading-snug",
                hot ? "border-brand/50 bg-brand/10" : "border-white/10 bg-white/[0.02]"
              )}
            >
              <span className={cn("block font-semibold", hot ? "text-brand" : "text-foreground")}>{d.label}</span>
              <span className="text-zinc-500">{d.note}</span>
            </div>
          );
        })}
      </div>
    </Window>
  );
}

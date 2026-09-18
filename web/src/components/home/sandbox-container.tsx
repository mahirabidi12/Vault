"use client";

import * as React from "react";
import { Ban, Cloud, FileKey2, Globe, Lock, Server, ShieldAlert, Skull } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  DECOYS,
  DEMO,
  SANDBOX_LIVE,
  SB_EVENTS,
  SB_FINDINGS,
  between,
  type SbEvent,
  type SbTag,
} from "@/lib/pipeline-flow";

const TAG: Record<SbTag, { label: string; cls: string }> = {
  decoy: { label: "DECOY OPENED", cls: "border-suspicious/40 bg-suspicious/10 text-suspicious" },
  canary: { label: "CANARY LEAKED", cls: "border-malicious/50 bg-malicious/15 text-malicious" },
  persist: { label: "PERSISTENCE", cls: "border-malicious/50 bg-malicious/15 text-malicious" },
  cond: { label: "ONLY IN RUN B", cls: "border-malicious/50 bg-malicious/15 text-malicious" },
  net: { label: "→ SINKHOLE", cls: "border-white/15 bg-white/5 text-zinc-400" },
};

const KIND_LABEL: Record<SbEvent["kind"], string> = {
  install: "install",
  proc: "process",
  file: "file",
  dns: "dns",
  http: "http",
  eval: "eval",
  cond: "compare",
};

/** The big "locked box" that shows what a package does when it is actually run. */
export function SandboxContainer({ t, className }: { t: number; className?: string }) {
  const run: "A" | "B" = t < 0.58 ? "A" : "B";
  const events = SB_EVENTS.filter((e) => e.at <= t);
  const net = events.filter((e) => e.kind === "dns" || e.kind === "http");
  const canary = t >= 0.38;
  const sealed = t >= 0.9;

  return (
    <div
      className={cn(
        "relative flex min-h-0 flex-col overflow-hidden rounded-2xl border border-white/15 bg-[#05060a]",
        "shadow-[0_0_80px_-20px_color-mix(in_oklch,var(--brand),transparent_40%)]",
        className
      )}
    >
      <IsolationRing tripped={canary} />

      {/* Header */}
      <div className="relative flex flex-wrap items-center gap-x-3 gap-y-1.5 border-b border-white/10 bg-white/[0.03] px-4 py-2.5">
        <span className="flex items-center gap-2 font-display text-[13px] font-semibold text-foreground">
          <Lock className="size-3.5 text-brand" />
          PkgGuard sandbox
        </span>
        <span className="hidden font-mono text-[10.5px] text-zinc-500 sm:inline">
          isolated microVM · no internet · unprivileged user · 120 s hard kill
        </span>
        <span className="ml-auto flex items-center gap-1.5">
          {!SANDBOX_LIVE && (
            <span className="rounded-full border border-suspicious/40 bg-suspicious/10 px-2 py-0.5 font-mono text-[10px] font-medium text-suspicious">
              In development
            </span>
          )}
          <span className="rounded-full border border-white/15 px-2 py-0.5 font-mono text-[10px] text-zinc-400">
            Illustrative example
          </span>
        </span>
      </div>

      {/* Body */}
      <div className="relative grid min-h-0 flex-1 grid-cols-1 overflow-hidden md:grid-cols-[0.85fr_1.5fr_1fr]">
        {/* Decoys */}
        <div className="hidden min-h-0 flex-col gap-2 border-r border-white/10 p-3 md:flex">
          <PanelTitle icon={FileKey2}>Planted decoys</PanelTitle>
          <ul className="flex flex-col gap-1.5">
            {DECOYS.map((d) => {
              const hit = t >= d.hitAt;
              return (
                <li
                  key={d.path}
                  className={cn(
                    "flex items-center justify-between gap-2 rounded-md border px-2 py-1.5 font-mono text-[10.5px] transition-all duration-300",
                    hit
                      ? "border-suspicious/50 bg-suspicious/10 text-suspicious"
                      : "border-white/10 bg-white/[0.02] text-zinc-400"
                  )}
                >
                  <span className="truncate">{d.path}</span>
                  <span className={cn("shrink-0 text-[9px] uppercase", hit ? "text-suspicious" : "text-zinc-600")}>
                    {hit ? "opened" : "fake"}
                  </span>
                </li>
              );
            })}
          </ul>
          <p className="mt-auto text-[10.5px] leading-snug text-zinc-500">
            Fake passwords and keys, each holding a unique marker. If a marker leaves the box, it is proof.
          </p>
        </div>

        {/* Live recording */}
        <div className="flex min-h-0 flex-col gap-2 p-3 md:border-r md:border-white/10">
          <div className="flex items-center gap-2">
            <PanelTitle icon={Server}>Live recording</PanelTitle>
            <span className="ml-auto flex gap-1 font-mono text-[10px]">
              <RunTab active={run === "A"}>Run A · normal</RunTab>
              <RunTab active={run === "B"}>Run B · hostile</RunTab>
            </span>
          </div>
          <ol
            aria-label="Illustrative sandbox event log"
            className="flex min-h-0 flex-1 flex-col justify-end gap-1 overflow-hidden font-mono text-[10.5px] leading-snug"
          >
            {events.slice(-9).map((e) => (
              <li
                key={`${e.at}-${e.text}`}
                className="animate-fade-up flex flex-wrap items-baseline gap-x-2 gap-y-0.5 rounded px-1.5 py-1 odd:bg-white/[0.025]"
              >
                <span className="w-12 shrink-0 text-zinc-600">{KIND_LABEL[e.kind]}</span>
                <span className={cn("min-w-0 break-all", e.tag && e.tag !== "net" ? "text-foreground" : "text-zinc-300")}>
                  <span className="mr-1.5 text-zinc-600">{e.run}</span>
                  {e.text}
                </span>
                {e.tag && (
                  <span className={cn("rounded border px-1.5 py-px text-[9px] font-semibold", TAG[e.tag].cls)}>
                    {TAG[e.tag].label}
                  </span>
                )}
              </li>
            ))}
            {events.length === 0 && <li className="text-zinc-600">waiting for install to start…</li>}
          </ol>
        </div>

        {/* Fake internet */}
        <div className="flex min-h-0 flex-col gap-2 p-3">
          <PanelTitle icon={Globe}>Fake internet</PanelTitle>
          <div className="hidden items-center gap-2 md:flex">
            <span className="flex size-8 shrink-0 items-center justify-center rounded-md border border-white/10 bg-white/[0.03] text-zinc-500">
              <Cloud className="size-4" />
            </span>
            <span className="flex h-px flex-1 items-center border-t border-dashed border-white/20">
              <span className="mx-auto -mt-px flex size-5 items-center justify-center rounded-full border border-malicious/50 bg-black text-malicious">
                <Ban className="size-3" />
              </span>
            </span>
            <span className="text-[10px] leading-tight text-zinc-500">
              real internet
              <br />
              unreachable
            </span>
          </div>
          <div className="hidden rounded-md border border-brand/30 bg-brand/5 px-2 py-1.5 md:block text-[10.5px] leading-snug text-zinc-300">
            <span className="font-semibold text-brand">Sinkhole</span> answers every DNS name and web request, and logs it.
          </div>
          <ul className="hidden min-h-0 flex-1 flex-col justify-end gap-1 overflow-hidden font-mono text-[10.5px] md:flex">
            {net.slice(-3).map((e) => (
              <li
                key={`${e.at}-${e.text}`}
                className="animate-fade-up truncate rounded border border-white/10 bg-white/[0.03] px-2 py-1 text-zinc-300"
              >
                <span className="text-zinc-500">{e.kind === "dns" ? "DNS " : "HTTP "}</span>
                {e.text.replace(/^(resolve|POST)\s+/, "").split("  ")[0]}
              </li>
            ))}
          </ul>
          {canary && (
            <div className="threat-box flex gap-2 rounded-md border border-malicious/50 bg-malicious/10 p-2 text-[10.5px] leading-snug text-malicious">
              <ShieldAlert className="mt-0.5 size-3.5 shrink-0" />
              <span>
                <strong className="font-semibold">Proof of exfiltration.</strong> Our fake npm token was inside an
                outgoing request.
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Two runs + findings */}
      <div className="relative flex flex-col gap-2 border-t border-white/10 bg-white/[0.02] px-4 py-2.5">
        <RunBar label="Run A · normal" progress={between(t, 0.04, 0.58)} marks={SB_EVENTS.filter((e) => e.run === "A")} span={[0.04, 0.58]} t={t} />
        <RunBar
          label="Run B · CI=true · clock +60 d · other host"
          progress={between(t, 0.6, 0.8)}
          marks={SB_EVENTS.filter((e) => e.run === "B")}
          span={[0.6, 0.8]}
          t={t}
        />
        <div className="flex min-h-[1.5rem] flex-wrap items-center gap-1.5">
          {SB_FINDINGS.filter((f) => t >= f.at).map((f) => (
            <span
              key={f.rule}
              className={cn(
                "animate-fade-up inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-mono text-[10px]",
                f.proof
                  ? "border-malicious/50 bg-malicious/10 text-malicious"
                  : "border-suspicious/40 bg-suspicious/10 text-suspicious"
              )}
            >
              {f.proof && <Skull className="size-3" />}
              {f.rule}
              <span className="opacity-70">{f.sev}</span>
            </span>
          ))}
          {sealed && (
            <span className="animate-fade-up ml-auto font-mono text-[10px] text-zinc-500">
              trace sealed · {DEMO.name}@{DEMO.version}
            </span>
          )}
        </div>
      </div>
    </div>
  );
}

function PanelTitle({ icon: Icon, children }: { icon: typeof Lock; children: React.ReactNode }) {
  return (
    <h4 className="flex items-center gap-1.5 font-mono text-[10.5px] font-medium uppercase tracking-wider text-zinc-500">
      <Icon className="size-3" />
      {children}
    </h4>
  );
}

function RunTab({ active, children }: { active: boolean; children: React.ReactNode }) {
  return (
    <span
      className={cn(
        "rounded-md border px-1.5 py-0.5 transition-colors",
        active ? "border-brand/50 bg-brand/10 text-brand" : "border-white/10 text-zinc-600"
      )}
    >
      {children}
    </span>
  );
}

function RunBar({
  label,
  progress,
  marks,
  span,
  t,
}: {
  label: string;
  progress: number;
  marks: SbEvent[];
  span: [number, number];
  t: number;
}) {
  return (
    <div className="flex items-center gap-2 font-mono text-[10px] text-zinc-500">
      <span className="w-[8.5rem] shrink-0 truncate sm:w-[15rem]">{label}</span>
      <div className="relative h-1.5 flex-1 rounded-full bg-white/10">
        <div className="h-full rounded-full bg-brand/70 transition-[width] duration-150" style={{ width: `${progress * 100}%` }} />
        {marks.map((m) => {
          const left = between(m.at, span[0], span[1]) * 100;
          const bad = m.tag === "canary" || m.tag === "persist" || m.tag === "cond";
          return (
            <span
              key={`${m.at}-${m.text}`}
              className={cn(
                "absolute top-1/2 size-1.5 -translate-x-1/2 -translate-y-1/2 rounded-full transition-opacity",
                t >= m.at ? "opacity-100" : "opacity-0",
                bad ? "bg-malicious shadow-[0_0_6px_var(--malicious)]" : "bg-zinc-300"
              )}
              style={{ left: `${left}%` }}
            />
          );
        })}
      </div>
    </div>
  );
}

/** Dashed animated border: the "nothing gets out" wall. Turns red when the box catches a leak attempt. */
function IsolationRing({ tripped }: { tripped: boolean }) {
  return (
    <svg aria-hidden className="pointer-events-none absolute inset-0 size-full">
      <rect
        x="1"
        y="1"
        rx="16"
        style={{ width: "calc(100% - 2px)", height: "calc(100% - 2px)" }}
        fill="none"
        strokeWidth="1.5"
        className={cn("flow transition-colors duration-500", tripped ? "stroke-malicious/60" : "stroke-brand/40")}
      />
    </svg>
  );
}

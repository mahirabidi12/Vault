"use client";

import { cn } from "@/lib/utils";
import type { StepId } from "@/components/home/pipeline-story";

type Tone = "cmd" | "info" | "ok" | "warn" | "verdict";
type Line = { step: StepId; text: string; tone: Tone };

export const STEP_ORDER: StepId[] = ["fetch", "intel", "code", "ai", "verdict"];

const LINES: Line[] = [
  { step: "fetch", text: "$ pkgguard scan esbuild@0.28.2", tone: "cmd" },
  { step: "fetch", text: "→ downloading tarball from registry.npmjs.org", tone: "info" },
  { step: "fetch", text: "✓ sha256 verified against registry", tone: "ok" },
  { step: "intel", text: "→ checking OSV.dev…", tone: "info" },
  { step: "intel", text: "✓ no known-malware advisory", tone: "ok" },
  { step: "intel", text: "→ checking SafeDep…", tone: "info" },
  { step: "intel", text: "✓ not flagged", tone: "ok" },
  { step: "code", text: "→ scanning 3 files (static analysis)…", tone: "info" },
  { step: "code", text: "⚠ runs a postinstall script", tone: "warn" },
  { step: "code", text: "⚠ downloads and runs a binary during install", tone: "warn" },
  { step: "ai", text: "→ 2 warnings — AI reading install.js…", tone: "info" },
  { step: "ai", text: "✓ downloads esbuild's own signed platform binary,", tone: "ok" },
  { step: "ai", text: "  verifies it, then runs --version to confirm", tone: "ok" },
  { step: "verdict", text: "verdict: no issues found", tone: "verdict" },
  { step: "verdict", text: "decided by: AI review · confidence: high", tone: "info" },
];

const TONE_CLASS: Record<Tone, string> = {
  cmd: "text-foreground",
  info: "text-muted-foreground",
  ok: "text-safe",
  warn: "text-suspicious",
  verdict: "text-safe font-semibold",
};

export function PipelineTerminal({ active, className }: { active: StepId; className?: string }) {
  const activeIndex = STEP_ORDER.indexOf(active);
  const visible = LINES.filter((l) => STEP_ORDER.indexOf(l.step) <= activeIndex);

  return (
    <div
      className={cn(
        "flex w-full flex-col overflow-hidden rounded-lg border border-border bg-[#0a0a0f] shadow-2xl shadow-black/20 dark:border-white/10",
        className
      )}
    >
      <div className="flex items-center gap-1.5 border-b border-white/10 bg-white/[0.03] px-3.5 py-2.5">
        <span className="size-2.5 rounded-full bg-[#ff5f56]" />
        <span className="size-2.5 rounded-full bg-[#ffbd2e]" />
        <span className="size-2.5 rounded-full bg-[#27c93f]" />
        <span className="ml-2 font-mono text-[11px] text-zinc-500">pkgguard — scan</span>
      </div>
      <div className="flex min-h-[19rem] flex-col gap-1.5 p-5 font-mono text-[13px] leading-relaxed">
        {visible.map((line, i) => (
          <p key={i} className={cn("animate-fade-up whitespace-pre", TONE_CLASS[line.tone])}>
            {line.text}
          </p>
        ))}
        <span className="mt-0.5 inline-block h-[1.1em] w-2 animate-pulse bg-zinc-500" />
      </div>
    </div>
  );
}

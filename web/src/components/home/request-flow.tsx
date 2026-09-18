"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { Terminal, Bot, Server, FileSearch, Box, Sparkles, ShieldCheck } from "lucide-react";

type Source = "cli" | "mcp";
type Outcome = "clean" | "flagged";

type Event = {
  source: Source;
  pkg: string;
  outcome: Outcome;
  detail: string;
};

const EVENTS: Event[] = [
  { source: "cli", pkg: "express@4.21.2", outcome: "clean", detail: "No issues found · cached" },
  { source: "mcp", pkg: "left-pad-pro@1.0.3", outcome: "flagged", detail: "MALICIOUS · install script reads ~/.ssh" },
  { source: "cli", pkg: "zod@4.6.5", outcome: "clean", detail: "No issues found · cached" },
  { source: "mcp", pkg: "chalk@6.0.0", outcome: "clean", detail: "No issues found · scanned 1.4s" },
  { source: "cli", pkg: "colors-js@2.1.0", outcome: "flagged", detail: "SUSPICIOUS · obfuscated postinstall" },
];

const CLI_PATH = "M 190 110 C 215 110, 205 220, 230 220";
const MCP_PATH = "M 190 330 C 215 330, 205 220, 230 220";
const CHECK_Y = [75, 220, 365];
const FAN_IN = CHECK_Y.map((y) => `M 380 220 C 425 220, 425 ${y}, 470 ${y}`);
const FAN_OUT = CHECK_Y.map((y) => `M 650 ${y} C 690 ${y}, 690 220, 730 220`);

const CHECKS = [
  { icon: FileSearch, title: "Static checks", sub: "reads the code, never runs it" },
  { icon: Box, title: "Dynamic checks", sub: "runs it in a sandbox, no internet" },
  { icon: Sparkles, title: "Agent checks", sub: "AI reads the code and the recording" },
];

export function RequestFlow() {
  const [i, setI] = React.useState(0);
  // A wave of light travels left to right across the diagram; each box glows by its distance from the wave.
  const [wave, setWave] = React.useState(450);
  React.useEffect(() => {
    const t = setInterval(() => setI((n) => (n + 1) % EVENTS.length), 2600);
    return () => clearInterval(t);
  }, []);
  React.useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const period = 5200;
    const start = performance.now();
    let raf = 0;
    const loop = (now: number) => {
      const p = ((now - start) % period) / period;
      setWave(-160 + p * 1220);
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, []);
  const glowAt = (cx: number) => Math.exp(-(((cx - wave) / 120) ** 2));
  const ev = EVENTS[i];
  const allPaths = [CLI_PATH, MCP_PATH, ...FAN_IN, ...FAN_OUT];

  return (
    <div className="mx-auto w-full max-w-5xl">
      <div className="overflow-x-auto rounded-2xl border border-border bg-card/40">
        <div className="relative min-w-[720px]">
          <div className="bg-grid pointer-events-none absolute inset-0 opacity-60 [mask-image:radial-gradient(ellipse_70%_70%_at_50%_50%,black,transparent)]" />
          <svg viewBox="0 0 900 440" className="relative block w-full" role="img" aria-label="CLI and MCP agent requests flow into the PkgGuard API, which runs static checks, dynamic checks and agent checks, and combines them into one verdict">
            {allPaths.map((d, k) => (
              <path key={k} d={d} fill="none" stroke="white" strokeOpacity="0.14" strokeWidth="1.5" />
            ))}
            {allPaths.map((d, k) => (
              <path key={`f${k}`} d={d} fill="none" stroke="white" strokeOpacity="0.5" strokeWidth="1.5" className="flow" />
            ))}

            <Packet path={CLI_PATH} dur="3.2s" begin="0s" />
            <Packet path={CLI_PATH} dur="3.2s" begin="1.6s" />
            <Packet path={MCP_PATH} dur="3.2s" begin="0.8s" />
            <Packet path={MCP_PATH} dur="3.2s" begin="2.4s" />
            {FAN_IN.map((d, k) => (
              <Packet key={`i${k}`} path={d} dur="2.2s" begin={`${k * 0.5}s`} />
            ))}
            {FAN_OUT.map((d, k) => (
              <Packet key={`o${k}`} path={d} dur="2s" begin={`${0.9 + k * 0.5}s`} />
            ))}

            <Node x={20} y={70} w={170} h={80} b={glowAt(105)} />
            <Node x={20} y={290} w={170} h={80} b={glowAt(105)} />
            <Node x={230} y={170} w={150} h={100} b={glowAt(305)} />
            {CHECK_Y.map((y) => (
              <Node key={y} x={470} y={y - 45} w={180} h={90} b={glowAt(560)} />
            ))}
            <Node x={730} y={170} w={150} h={100} b={glowAt(805)} />
          </svg>

          <Label left="2.2%" top="15.9%" w="18.9%" h="18.2%" icon={<Terminal className="size-4" />} title="pkgguard CLI" sub="npm install, checked" />
          <Label left="2.2%" top="65.9%" w="18.9%" h="18.2%" icon={<Bot className="size-4" />} title="MCP agent tool" sub="Claude · Cursor · any agent" />
          <Label left="25.6%" top="38.6%" w="16.7%" h="22.7%" icon={<Server className="size-4" />} title="PkgGuard API" sub="one verdict per package" center />
          {CHECKS.map((c, k) => (
            <Label
              key={c.title}
              left="52.2%"
              top={`${((CHECK_Y[k] - 45) / 440) * 100}%`}
              w="20%"
              h="20.5%"
              icon={<c.icon className="size-4" />}
              title={c.title}
              sub={c.sub}
            />
          ))}
          <Label left="81.1%" top="38.6%" w="16.7%" h="22.7%" icon={<ShieldCheck className="size-4" />} title="Verdict" sub="safe · suspicious · malicious" center />
        </div>
      </div>

      {/* live request log */}
      <div className="mt-4 flex items-center gap-3 rounded-xl border border-border bg-card/60 px-4 py-3 font-mono text-xs sm:text-[13px]">
        <span className="relative flex size-2 shrink-0">
          <span className="absolute inline-flex size-full animate-ping rounded-full bg-white/60" />
          <span className="relative inline-flex size-2 rounded-full bg-white" />
        </span>
        <span key={i} className="flex min-w-0 flex-1 animate-fade-up flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className="text-muted-foreground">{ev.source === "cli" ? "cli" : "mcp"}</span>
          <span className="text-muted-foreground/50">→</span>
          <span className="text-foreground">{ev.pkg}</span>
          <span className="text-muted-foreground/50">→</span>
          <span className={ev.outcome === "clean" ? "text-safe" : "text-malicious"}>{ev.detail}</span>
        </span>
      </div>
    </div>
  );
}

function Packet({ path, dur, begin }: { path: string; dur: string; begin: string }) {
  return (
    <circle r="4" fill="white">
      <animateMotion dur={dur} begin={begin} repeatCount="indefinite" path={path} />
    </circle>
  );
}

function Node({ x, y, w, h, b }: { x: number; y: number; w: number; h: number; b: number }) {
  return (
    <rect
      x={x}
      y={y}
      width={w}
      height={h}
      rx="14"
      fill="#050505"
      stroke="white"
      strokeOpacity={0.16 + 0.84 * b}
      strokeWidth={1.5 + 1.3 * b}
    />
  );
}

function Label({
  left, top, w, h, icon, title, sub, center,
}: {
  left: string; top: string; w: string; h: string; icon: React.ReactNode; title: string; sub: string; center?: boolean;
}) {
  return (
    <div
      className={cn("absolute flex flex-col justify-center gap-1 px-4", center && "items-center text-center")}
      style={{ left, top, width: w, height: h }}
    >
      <span className="flex items-center gap-2 text-sm font-semibold text-foreground">
        {icon}
        {title}
      </span>
      <span className="text-[11px] leading-tight text-muted-foreground">{sub}</span>
    </div>
  );
}

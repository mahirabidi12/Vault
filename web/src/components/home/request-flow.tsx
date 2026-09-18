"use client";

import * as React from "react";
import { cn } from "@/lib/utils";
import { Terminal, Bot, Server, Database } from "lucide-react";

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

const CLI_PATH = "M 190 110 C 290 110, 300 220, 400 220";
const MCP_PATH = "M 190 330 C 290 330, 300 220, 400 220";
const DB_PATH = "M 560 220 L 700 220";

export function RequestFlow() {
  const [i, setI] = React.useState(0);
  React.useEffect(() => {
    const t = setInterval(() => setI((n) => (n + 1) % EVENTS.length), 2600);
    return () => clearInterval(t);
  }, []);
  const ev = EVENTS[i];

  return (
    <div className="mx-auto w-full max-w-5xl">
      <div className="overflow-x-auto rounded-2xl border border-border bg-card/40">
        <div className="relative min-w-[720px]">
          <div className="bg-grid pointer-events-none absolute inset-0 opacity-60 [mask-image:radial-gradient(ellipse_70%_70%_at_50%_50%,black,transparent)]" />
          <svg viewBox="0 0 900 440" className="relative block w-full" role="img" aria-label="CLI and MCP agent requests flowing into the PkgGuard API and its shared database of verdicts">
            {/* lanes */}
            {[CLI_PATH, MCP_PATH, DB_PATH].map((d, k) => (
              <path key={k} d={d} fill="none" stroke="white" strokeOpacity="0.14" strokeWidth="1.5" />
            ))}
            {[CLI_PATH, MCP_PATH, DB_PATH].map((d, k) => (
              <path key={`f${k}`} d={d} fill="none" stroke="white" strokeOpacity="0.5" strokeWidth="1.5" className="flow" />
            ))}

            {/* request packets */}
            <Packet path={CLI_PATH} dur="3.2s" begin="0s" />
            <Packet path={CLI_PATH} dur="3.2s" begin="1.6s" />
            <Packet path={MCP_PATH} dur="3.2s" begin="0.8s" />
            <Packet path={MCP_PATH} dur="3.2s" begin="2.4s" />
            <Packet path={DB_PATH} dur="1.6s" begin="0.3s" />
            <Packet path={DB_PATH} dur="1.6s" begin="1.1s" />

            {/* nodes */}
            <Node x={20} y={70} w={170} h={80} active={ev.source === "cli"} />
            <Node x={20} y={290} w={170} h={80} active={ev.source === "mcp"} />
            <Node x={400} y={170} w={160} h={100} active glow />
            <Node x={700} y={160} w={180} h={120} active />
          </svg>

          {/* node labels as HTML so text stays crisp */}
          <Label left="2.2%" top="15.9%" w="18.9%" h="18.2%" icon={<Terminal className="size-4" />} title="pkgguard CLI" sub="npm install, checked" />
          <Label left="2.2%" top="65.9%" w="18.9%" h="18.2%" icon={<Bot className="size-4" />} title="MCP agent tool" sub="Claude · Cursor · any agent" />
          <Label left="44.4%" top="38.6%" w="17.8%" h="22.7%" icon={<Server className="size-4" />} title="PkgGuard API" sub="one verdict per package" center />
          <Label left="77.8%" top="36.4%" w="20%" h="27.3%" icon={<Database className="size-4" />} title="Verdict database" sub="every scanned package" center />
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

function Node({ x, y, w, h, active, glow }: { x: number; y: number; w: number; h: number; active?: boolean; glow?: boolean }) {
  return (
    <rect
      x={x}
      y={y}
      width={w}
      height={h}
      rx="14"
      fill="#050505"
      stroke="white"
      strokeOpacity={active ? 0.55 : 0.15}
      strokeWidth="1.5"
      style={glow ? { filter: "drop-shadow(0 0 18px rgba(255,255,255,0.12))" } : undefined}
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

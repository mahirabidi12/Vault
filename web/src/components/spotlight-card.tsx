"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

export function SpotlightCard({ children, className, beam }: { children: React.ReactNode; className?: string; beam?: boolean }) {
  const ref = React.useRef<HTMLDivElement>(null);
  const onMove = (e: React.MouseEvent) => {
    const r = ref.current?.getBoundingClientRect();
    if (!r) return;
    ref.current!.style.setProperty("--mx", `${e.clientX - r.left}px`);
    ref.current!.style.setProperty("--my", `${e.clientY - r.top}px`);
  };
  return (
    <div
      ref={ref}
      onMouseMove={onMove}
      className={cn("group relative overflow-hidden rounded-2xl border border-border bg-card/50 transition-colors hover:border-white/25", className)}
    >
      {beam && <div className="border-beam pointer-events-none absolute inset-0 rounded-[inherit]" />}
      <div
        className="pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100"
        style={{ background: "radial-gradient(360px circle at var(--mx,50%) var(--my,50%), rgba(255,255,255,0.09), transparent 65%)" }}
      />
      <div className="relative h-full">{children}</div>
    </div>
  );
}

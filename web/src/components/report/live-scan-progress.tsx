"use client";

import * as React from "react";
import { Progress } from "@/components/ui/progress";
import { Loader2, Check, Download, Radar, FileSearch, Code2, Sparkles, ScanLine } from "lucide-react";
import { cn } from "@/lib/utils";
import type { VerdictRecord } from "@/lib/types/domain";

const STEPS = [
  { key: "fetch", label: "Fetching package", icon: Download },
  { key: "intel", label: "Checking threat intelligence", icon: Radar },
  { key: "metadata", label: "Reading package info", icon: FileSearch },
  { key: "static", label: "Scanning code", icon: Code2 },
  { key: "ai", label: "AI triage", icon: Sparkles },
];

const TOTAL_MS = 3300;

export function LiveScanProgress({ record }: { record: VerdictRecord }) {
  const [now, setNow] = React.useState(() => Date.now());

  React.useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 60);
    return () => clearInterval(id);
  }, []);

  const startedAt = new Date(record.requestedAt).getTime();
  const elapsed = Math.max(0, now - startedAt);
  const fraction = record.status === "SCANNING" || record.status === "PENDING"
    ? Math.min(0.97, elapsed / TOTAL_MS)
    : 1;
  const activeStepIndex = Math.min(STEPS.length - 1, Math.floor(fraction * STEPS.length));

  return (
    <div className="mx-auto flex max-w-2xl flex-col items-center gap-8 px-4 py-24 text-center">
      <div className="relative flex size-20 items-center justify-center">
        <span className="absolute inset-0 rounded-full bg-brand/10 animate-pulse-ring" />
        <ScanLine className="size-9 text-brand" />
      </div>

      <div className="flex flex-col gap-2">
        <h1 className="text-xl font-semibold tracking-tight">
          Scanning <span className="font-mono">{record.package.name}@{record.package.version}</span>
        </h1>
        <p className="text-sm text-muted-foreground">
          Nobody has scanned this exact version yet. PkgGuard is analyzing it now — this result will be
          instant for everyone after this.
        </p>
      </div>

      <div className="w-full max-w-sm">
        <Progress value={fraction * 100} className="h-1.5" />
      </div>

      <ol className="flex w-full max-w-sm flex-col gap-2.5 text-left">
        {STEPS.map((step, i) => {
          const Icon = step.icon;
          const state = i < activeStepIndex ? "done" : i === activeStepIndex ? "active" : "pending";
          return (
            <li
              key={step.key}
              className={cn(
                "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors",
                state === "active" && "bg-brand/10 text-foreground",
                state === "done" && "text-muted-foreground",
                state === "pending" && "text-muted-foreground/50"
              )}
            >
              <span className="flex size-6 shrink-0 items-center justify-center">
                {state === "done" ? (
                  <Check className="size-4 text-safe" />
                ) : state === "active" ? (
                  <Loader2 className="size-4 animate-spin text-brand" />
                ) : (
                  <Icon className="size-4" />
                )}
              </span>
              {step.label}
            </li>
          );
        })}
      </ol>
    </div>
  );
}

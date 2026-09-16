import { cn } from "@/lib/utils";
import {
  verdictStyle,
  statusStyle,
  DECIDED_BY_LABEL,
  DECIDED_BY_ICON,
  LAYER_LABEL,
  LAYER_ICON,
  SEVERITY_LABEL,
  severityClass,
} from "@/lib/verdict";
import type { DecidedBy, FindingLayer, ScanStatus, Severity, Verdict } from "@/lib/types/domain";
import { Terminal, Repeat2, Database } from "lucide-react";

export function VerdictBadge({
  verdict,
  size = "md",
  className,
}: {
  verdict: Verdict | null | undefined;
  size?: "sm" | "md" | "lg";
  className?: string;
}) {
  const s = verdictStyle(verdict);
  const Icon = s.icon;
  const sizeClass =
    size === "lg"
      ? "gap-2 rounded-xl px-4 py-2 text-base"
      : size === "sm"
        ? "gap-1 rounded-md px-1.5 py-0.5 text-xs"
        : "gap-1.5 rounded-lg px-2.5 py-1 text-sm";
  return (
    <span
      className={cn(
        "inline-flex items-center border font-medium",
        s.badgeClass,
        sizeClass,
        className
      )}
    >
      <Icon className={size === "lg" ? "size-5" : size === "sm" ? "size-3" : "size-4"} />
      {s.label}
    </span>
  );
}

export function StatusBadge({ status, className }: { status: ScanStatus; className?: string }) {
  const s = statusStyle(status);
  const Icon = s.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-sm font-medium",
        s.className,
        className
      )}
    >
      <Icon className={cn("size-4", s.spin && "animate-spin")} />
      {s.label}
    </span>
  );
}

export function DecidedByPill({ decidedBy, className }: { decidedBy?: DecidedBy | null; className?: string }) {
  if (!decidedBy) return null;
  const Icon = DECIDED_BY_ICON[decidedBy];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/70 px-2.5 py-1 text-xs font-medium text-muted-foreground",
        className
      )}
    >
      <Icon className="size-3.5" />
      {DECIDED_BY_LABEL[decidedBy]}
    </span>
  );
}

export function ConfidencePill({ confidence, className }: { confidence?: string | null; className?: string }) {
  if (!confidence) return null;
  return (
    <span className={cn("inline-flex items-center rounded-full border border-border px-2.5 py-1 text-xs font-medium text-muted-foreground", className)}>
      {confidence.charAt(0) + confidence.slice(1).toLowerCase()} confidence
    </span>
  );
}

export function LayerBadge({ layer, className }: { layer: FindingLayer; className?: string }) {
  const Icon = LAYER_ICON[layer];
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/60 px-2 py-0.5 text-xs font-medium text-muted-foreground", className)}>
      <Icon className="size-3" />
      {LAYER_LABEL[layer]}
    </span>
  );
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded-md border px-1.5 py-0.5 text-[11px] font-semibold uppercase tracking-wide", severityClass(severity), className)}>
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

export function InstallTimeBadge({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-md border border-suspicious/30 bg-suspicious-bg px-1.5 py-0.5 text-[11px] font-semibold text-suspicious", className)}>
      <Terminal className="size-3" />
      Runs during install
    </span>
  );
}

export function OccurrencesBadge({ count, className }: { count: number; className?: string }) {
  if (count <= 1) return null;
  return (
    <span className={cn("inline-flex items-center gap-1 rounded-md border border-border bg-muted px-1.5 py-0.5 text-[11px] font-medium text-muted-foreground", className)}>
      <Repeat2 className="size-3" />×{count}
    </span>
  );
}

export function OsvImportBadge({ className }: { className?: string }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/60 px-2.5 py-1 text-xs font-medium text-muted-foreground", className)}>
      <Database className="size-3.5" />
      Source: OSV
    </span>
  );
}

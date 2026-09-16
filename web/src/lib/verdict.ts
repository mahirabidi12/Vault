/**
 * Single source of truth for how a verdict/status/layer/decidedBy is
 * labeled, colored and iconed across the whole site. See BRIEF.md §5.4:
 * never say "Safe" as a guarantee, always show confidence + decidedBy,
 * color is never the only signal.
 */
import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ShieldQuestion,
  Loader2,
  Clock,
  XCircle,
  MinusCircle,
  Radar,
  FileCog,
  Code2,
  Sparkles,
  UserCheck,
  type LucideIcon,
} from "lucide-react";
import type { Verdict, ScanStatus, DecidedBy } from "@/lib/types/domain";
import type { FindingLayer, Severity } from "@/lib/types/domain";

export interface VerdictStyle {
  label: string;
  shortLabel: string;
  description: string;
  icon: LucideIcon;
  colorVar: "safe" | "suspicious" | "malicious" | "pending";
  badgeClass: string;
  dotClass: string;
  textClass: string;
}

const VERDICT_STYLES: Record<Verdict, VerdictStyle> = {
  SAFE: {
    label: "No issues found",
    shortLabel: "No issues found",
    description:
      "Nothing in threat intelligence, package metadata or code triggered a warning. This is not a guarantee.",
    icon: ShieldCheck,
    colorVar: "safe",
    badgeClass: "bg-safe-bg text-safe border-safe/20",
    dotClass: "bg-safe",
    textClass: "text-safe",
  },
  SUSPICIOUS: {
    label: "Suspicious",
    shortLabel: "Suspicious",
    description:
      "Something about this package is unusual enough to warrant a closer look before you install it.",
    icon: ShieldAlert,
    colorVar: "suspicious",
    badgeClass: "bg-suspicious-bg text-suspicious border-suspicious/20",
    dotClass: "bg-suspicious",
    textClass: "text-suspicious",
  },
  MALICIOUS: {
    label: "Malicious",
    shortLabel: "Malicious",
    description: "PkgGuard has strong evidence this package is harmful. Don't install it.",
    icon: ShieldX,
    colorVar: "malicious",
    badgeClass: "bg-malicious-bg text-malicious border-malicious/20",
    dotClass: "bg-malicious",
    textClass: "text-malicious",
  },
};

export function verdictStyle(verdict: Verdict | null | undefined): VerdictStyle {
  if (verdict && verdict in VERDICT_STYLES) return VERDICT_STYLES[verdict];
  return {
    label: "Unknown",
    shortLabel: "Unknown",
    description: "No verdict yet.",
    icon: ShieldQuestion,
    colorVar: "pending",
    badgeClass: "bg-pending-bg text-pending border-pending/20",
    dotClass: "bg-pending",
    textClass: "text-pending",
  };
}

export interface StatusStyle {
  label: string;
  icon: LucideIcon;
  spin?: boolean;
  className: string;
}

export function statusStyle(status: ScanStatus): StatusStyle {
  switch (status) {
    case "PENDING":
      return {
        label: "Queued",
        icon: Clock,
        className: "text-pending bg-pending-bg border-pending/20",
      };
    case "SCANNING":
      return {
        label: "Scanning",
        icon: Loader2,
        spin: true,
        className: "text-pending bg-pending-bg border-pending/20",
      };
    case "COMPLETE":
      return {
        label: "Complete",
        icon: ShieldCheck,
        className: "text-safe bg-safe-bg border-safe/20",
      };
    case "FAILED":
      return {
        label: "Failed",
        icon: XCircle,
        className: "text-malicious bg-malicious-bg border-malicious/20",
      };
    case "SKIPPED":
      return {
        label: "Skipped",
        icon: MinusCircle,
        className: "text-muted-foreground bg-muted border-border",
      };
  }
}

export const DECIDED_BY_LABEL: Record<DecidedBy, string> = {
  intel: "Threat intelligence",
  rules: "Automated rules",
  ai: "AI review",
  human: "Human verified",
};

export const DECIDED_BY_ICON: Record<DecidedBy, LucideIcon> = {
  intel: Radar,
  rules: FileCog,
  ai: Sparkles,
  human: UserCheck,
};

export const LAYER_LABEL: Record<FindingLayer, string> = {
  intel: "Threat intelligence",
  metadata: "Package info",
  static: "Code",
};

export const LAYER_ICON: Record<FindingLayer, LucideIcon> = {
  intel: Radar,
  metadata: FileCog,
  static: Code2,
};

export const SEVERITY_ORDER: Record<Severity, number> = {
  HIGH: 0,
  MEDIUM: 1,
  LOW: 2,
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  HIGH: "High",
  MEDIUM: "Medium",
  LOW: "Low",
};

export function severityClass(severity: Severity): string {
  switch (severity) {
    case "HIGH":
      return "bg-malicious-bg text-malicious border-malicious/20";
    case "MEDIUM":
      return "bg-suspicious-bg text-suspicious border-suspicious/20";
    case "LOW":
      return "bg-muted text-muted-foreground border-border";
  }
}

export const CONFIDENCE_LABEL: Record<string, string> = {
  HIGH: "High confidence",
  MEDIUM: "Medium confidence",
  LOW: "Low confidence",
};

"use client";

import { useStats } from "@/lib/queries";
import { Skeleton } from "@/components/ui/skeleton";
import { ShieldCheck, ShieldAlert, ShieldX, ScanSearch } from "lucide-react";

export function LiveStats() {
  const { data, isLoading } = useStats();

  const items = [
    { label: "Packages scanned", value: data?.totalScanned, icon: ScanSearch, tone: "text-foreground" },
    { label: "No issues found", value: data?.safeCount, icon: ShieldCheck, tone: "text-safe" },
    { label: "Suspicious", value: data?.suspiciousCount, icon: ShieldAlert, tone: "text-suspicious" },
    { label: "Malicious caught", value: data?.maliciousCount, icon: ShieldX, tone: "text-malicious" },
  ];

  return (
    <dl className="grid grid-cols-2 gap-4 sm:grid-cols-4">
      {items.map((item) => (
        <div
          key={item.label}
          className="flex flex-col items-center gap-1.5 rounded-lg border border-border/70 bg-card/50 px-4 py-5 text-center backdrop-blur-sm"
        >
          <item.icon className={`size-5 ${item.tone}`} />
          {isLoading ? (
            <Skeleton className="h-7 w-16" />
          ) : (
            <dd className={`text-2xl font-semibold tabular-nums ${item.tone}`}>
              {item.value?.toLocaleString()}
            </dd>
          )}
          <dt className="text-xs text-muted-foreground">{item.label}</dt>
        </div>
      ))}
    </dl>
  );
}

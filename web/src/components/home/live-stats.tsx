"use client";

import * as React from "react";
import { SpotlightCard } from "@/components/spotlight-card";
import { useStats } from "@/lib/queries";
import { Skeleton } from "@/components/ui/skeleton";
import { ShieldCheck, ShieldAlert, ShieldX, ScanSearch } from "lucide-react";

function CountUp({ value }: { value: number }) {
  const [n, setN] = React.useState(0);
  React.useEffect(() => {
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const k = Math.min(1, (now - start) / 1200);
      setN(Math.round(value * (1 - (1 - k) ** 3)));
      if (k < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [value]);
  return <>{n.toLocaleString()}</>;
}

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
        <SpotlightCard key={item.label} className="rounded-xl">
        <div className="flex flex-col items-center gap-1.5 px-4 py-5 text-center">
          <item.icon className={`size-5 ${item.tone}`} />
          {isLoading ? (
            <Skeleton className="h-7 w-16" />
          ) : (
            <dd className={`text-2xl font-semibold tabular-nums ${item.tone}`}>
              {item.value !== undefined && <CountUp value={item.value} />}
            </dd>
          )}
          <dt className="text-xs text-muted-foreground">{item.label}</dt>
        </div>
        </SpotlightCard>
      ))}
    </dl>
  );
}

"use client";

import Link from "next/link";
import { useFeed } from "@/lib/queries";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge } from "@/components/verdict-ui";
import { packageHref } from "@/lib/package-ref";
import { formatRelativeTime } from "@/lib/format";
import { ArrowRight } from "lucide-react";

export function RecentThreats() {
  const { data, isLoading } = useFeed();
  const items = data?.slice(0, 4) ?? [];

  return (
    <div className="flex flex-col gap-3">
      {isLoading &&
        Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-16 w-full rounded-xl" />)}

      {!isLoading &&
        items.map(({ record }) => (
          <Link
            key={`${record.package.name}@${record.package.version}`}
            href={packageHref(record.package.name, record.package.version)}
            className="group flex items-center justify-between gap-3 rounded-xl border border-border bg-card/50 px-4 py-3 transition-colors hover:border-brand/40 hover:bg-accent/40"
          >
            <div className="flex min-w-0 flex-col gap-0.5">
              <span className="truncate font-mono text-sm font-medium">
                {record.package.name}
                <span className="text-muted-foreground">@{record.package.version}</span>
              </span>
              <span className="truncate text-xs text-muted-foreground">{record.summary}</span>
            </div>
            <div className="flex shrink-0 items-center gap-3">
              <span className="hidden text-xs text-muted-foreground sm:inline">
                {formatRelativeTime(record.analyzedAt)}
              </span>
              <VerdictBadge verdict={record.verdict} size="sm" />
              <ArrowRight className="size-3.5 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
            </div>
          </Link>
        ))}
    </div>
  );
}

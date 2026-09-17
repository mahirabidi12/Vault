import Link from "next/link";
import type { Metadata } from "next";
import { getFeed } from "@/lib/api";
import { packageHref } from "@/lib/package-ref";
import { VerdictBadge, DecidedByPill, OsvImportBadge } from "@/components/verdict-ui";
import { formatDateTime, formatRelativeTime } from "@/lib/format";
import { Radar } from "lucide-react";

export const metadata: Metadata = { title: "Threat feed" };

export default async function FeedPage() {
  const items = await getFeed(50);

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-6 px-4 py-10 sm:px-6">
      <div className="flex flex-col gap-2">
        <span className="inline-flex w-fit items-center gap-1.5 rounded-full border border-border bg-card/60 px-3 py-1.5 text-muted-foreground kicker">
          <Radar className="size-3.5" />
          Live threat feed
        </span>
        <h1 className="font-display text-2xl font-semibold tracking-tight">Recently caught packages</h1>
        <p className="text-sm text-muted-foreground">
          Every suspicious or malicious verdict PkgGuard has produced, newest first.
        </p>
      </div>

      <div className="flex flex-col gap-3">
        {items.length === 0 && (
          <p className="rounded-xl border border-dashed border-border p-6 text-center text-sm text-muted-foreground">
            Nothing caught yet.
          </p>
        )}
        {items.map(({ record }) => (
          <Link
            key={`${record.package.name}@${record.package.version}-${record.scanId}`}
            href={packageHref(record.package.name, record.package.version)}
            className="flex flex-col gap-3 rounded-lg border border-border bg-card/60 p-5 transition-colors hover:border-brand/40 hover:bg-accent/20"
          >
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-sm font-medium">
                {record.package.name}
                <span className="text-muted-foreground">@{record.package.version}</span>
              </span>
              <span className="text-xs text-muted-foreground" title={formatDateTime(record.analyzedAt)}>
                {formatRelativeTime(record.analyzedAt)}
              </span>
            </div>
            <p className="text-sm text-foreground/85">{record.summary}</p>
            <div className="flex flex-wrap items-center gap-2">
              <VerdictBadge verdict={record.verdict} size="sm" />
              <DecidedByPill decidedBy={record.decidedBy} />
              {record.source === "osv-import" && <OsvImportBadge />}
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}

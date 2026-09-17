import Link from "next/link";
import type { Metadata } from "next";
import { search } from "@/lib/api";
import { packageHref } from "@/lib/package-ref";
import { VerdictBadge, StatusBadge } from "@/components/verdict-ui";
import { SearchBar } from "@/components/search-bar";
import { Button } from "@/components/ui/button";
import { formatRelativeTime } from "@/lib/format";
import { ScanSearch, ArrowRight, PackageSearch } from "lucide-react";

type Props = { searchParams: Promise<{ q?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  const { q } = await searchParams;
  return { title: q ? `Search: ${q}` : "Search" };
}

export default async function SearchPage({ searchParams }: Props) {
  const { q = "" } = await searchParams;
  const results = q ? await search(q) : [];
  const exactMatch = results.some((r) => r.package.name.toLowerCase() === q.trim().toLowerCase());

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-6 px-4 py-10 sm:px-6">
      <SearchBar variant="hero" placeholder="Search a package…" />

      {!q && (
        <p className="text-sm text-muted-foreground">Search for a package to see its PkgGuard report.</p>
      )}

      {q && (
        <>
          <p className="text-sm text-muted-foreground">
            {results.length} result{results.length !== 1 ? "s" : ""} for <span className="font-mono text-foreground">&quot;{q}&quot;</span>
          </p>

          <div className="flex flex-col gap-2.5">
            {results.map((record) => (
              <Link
                key={`${record.package.name}@${record.package.version}`}
                href={packageHref(record.package.name, record.package.version)}
                className="group flex items-center justify-between gap-3 rounded-xl border border-border bg-card/60 px-4 py-3.5 transition-colors hover:border-brand/40 hover:bg-accent/30"
              >
                <div className="flex min-w-0 flex-col gap-0.5">
                  <span className="truncate font-mono text-sm font-medium">
                    {record.package.name}
                    <span className="text-muted-foreground">@{record.package.version}</span>
                  </span>
                  {record.summary && <span className="truncate text-xs text-muted-foreground">{record.summary}</span>}
                </div>
                <div className="flex shrink-0 items-center gap-3">
                  <span className="hidden text-xs text-muted-foreground sm:inline">
                    {formatRelativeTime(record.analyzedAt)}
                  </span>
                  {record.status === "COMPLETE" ? (
                    <VerdictBadge verdict={record.verdict} size="sm" />
                  ) : (
                    <StatusBadge status={record.status} />
                  )}
                  <ArrowRight className="size-3.5 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
                </div>
              </Link>
            ))}
          </div>

          {!exactMatch && (
            <div className="mt-2 flex flex-col items-start gap-3 rounded-lg border border-dashed border-border bg-card/40 p-6">
              <span className="flex size-9 items-center justify-center rounded-lg bg-brand/10 text-brand">
                <PackageSearch className="size-4.5" />
              </span>
              <p className="text-sm text-muted-foreground">
                Not finding <span className="font-mono text-foreground">{q}</span>? If that&apos;s an exact npm
                package name, PkgGuard can scan it right now.
              </p>
              <Button render={<Link href={packageHref(q)} />} nativeButton={false}>
                <ScanSearch className="size-4" />
                Scan &quot;{q}&quot; now
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

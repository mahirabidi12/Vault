import Link from "next/link";
import type { Metadata } from "next";
import { search } from "@/lib/api";
import { packageHref, parsePackageQuery } from "@/lib/package-ref";
import { VerdictBadge, StatusBadge } from "@/components/verdict-ui";
import { SearchBar } from "@/components/search-bar";
import { Button } from "@/components/ui/button";
import { formatRelativeTime } from "@/lib/format";
import { verdictStyle, DECIDED_BY_ICON, DECIDED_BY_LABEL, CONFIDENCE_LABEL } from "@/lib/verdict";
import { cn } from "@/lib/utils";
import { ScanSearch, ArrowRight, PackageSearch, Clock } from "lucide-react";

type Props = { searchParams: Promise<{ q?: string }> };

export async function generateMetadata({ searchParams }: Props): Promise<Metadata> {
  const { q } = await searchParams;
  return { title: q ? `Search: ${q}` : "Search" };
}

export default async function SearchPage({ searchParams }: Props) {
  const { q = "" } = await searchParams;
  const { name: qName, version: qVersion } = parsePackageQuery(q);
  const results = q ? await search(qName) : [];
  const exactMatch = results.some(
    (r) => r.package.name.toLowerCase() === qName.toLowerCase() && (!qVersion || r.package.version === qVersion)
  );

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-8 px-4 pb-24 pt-14 sm:px-6 sm:pt-20">
      <div className="flex flex-col gap-3">
        <p className="kicker text-brand">Search</p>
        <h1 className="text-balance text-[clamp(1.9rem,4vw,2.8rem)] font-semibold leading-[1.05] tracking-[-0.04em]">
          {q ? (
            <>
              Results for <span className="font-mono text-[0.9em] text-fade">{q}</span>
            </>
          ) : (
            "Find a package"
          )}
        </h1>
        <p className="text-sm text-muted-foreground">
          {q
            ? results.length > 0
              ? `${results.length} scanned version${results.length !== 1 ? "s" : ""} found. Open one to see the full evidence.`
              : "Nothing scanned under that name yet."
            : "Search for a package to see its PkgGuard report."}
        </p>
      </div>

      <SearchBar variant="hero" placeholder="Search a package, e.g. express or @babel/core" />

      {q && (
        <>
          <ul className="flex flex-col gap-3">
            {results.map((record) => {
              const style = verdictStyle(record.verdict);
              const Icon = style.icon;
              const complete = record.status === "COMPLETE";
              const DecidedIcon = record.decidedBy ? DECIDED_BY_ICON[record.decidedBy] : null;
              return (
                <li key={`${record.package.name}@${record.package.version}`}>
                  <Link
                    href={packageHref(record.package.name, record.package.version)}
                    className="group relative flex items-center gap-4 overflow-hidden rounded-2xl border border-white/10 bg-white/[0.025] p-4 pr-5 transition-all duration-300 hover:-translate-y-0.5 hover:border-white/25 hover:bg-white/[0.05] hover:shadow-[0_12px_40px_-12px_rgba(255,255,255,0.12)] sm:p-5"
                  >
                    <span
                      aria-hidden
                      className={cn("absolute inset-y-0 left-0 w-1", complete ? style.dotClass : "bg-white/20")}
                    />
                    <span
                      className={cn(
                        "flex size-12 shrink-0 items-center justify-center rounded-xl border",
                        complete ? style.badgeClass : "border-white/10 bg-white/5 text-muted-foreground"
                      )}
                    >
                      <Icon className="size-6" />
                    </span>

                    <div className="flex min-w-0 flex-1 flex-col gap-1.5">
                      <div className="flex flex-wrap items-baseline gap-x-2 gap-y-1">
                        <span className="truncate font-mono text-base font-semibold sm:text-lg">
                          {record.package.name}
                        </span>
                        <span className="rounded-md border border-white/10 bg-white/5 px-1.5 py-0.5 font-mono text-xs text-muted-foreground">
                          v{record.package.version}
                        </span>
                      </div>
                      {record.summary && (
                        <span className="line-clamp-2 text-sm leading-snug text-muted-foreground">{record.summary}</span>
                      )}
                      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground/80">
                        <span className="inline-flex items-center gap-1.5">
                          <Clock className="size-3.5" />
                          {formatRelativeTime(record.analyzedAt)}
                        </span>
                        {record.decidedBy && DecidedIcon && (
                          <span className="inline-flex items-center gap-1.5">
                            <DecidedIcon className="size-3.5" />
                            {DECIDED_BY_LABEL[record.decidedBy]}
                          </span>
                        )}
                        {record.confidence && <span>{CONFIDENCE_LABEL[record.confidence]}</span>}
                      </div>
                    </div>

                    <div className="flex shrink-0 flex-col items-end gap-2 sm:flex-row sm:items-center sm:gap-4">
                      {complete ? <VerdictBadge verdict={record.verdict} /> : <StatusBadge status={record.status} />}
                      <ArrowRight className="hidden size-4 text-muted-foreground transition-transform group-hover:translate-x-1 group-hover:text-foreground sm:block" />
                    </div>
                  </Link>
                </li>
              );
            })}
          </ul>

          {!exactMatch && (
            <div className="relative flex flex-col items-start gap-4 overflow-hidden rounded-2xl border border-dashed border-white/15 bg-gradient-to-br from-white/[0.04] to-transparent p-6 sm:flex-row sm:items-center sm:justify-between sm:p-7">
              <div className="flex items-start gap-4">
                <span className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5">
                  <PackageSearch className="size-5" />
                </span>
                <div>
                  <p className="font-semibold">
                    Not seeing <span className="font-mono">{q}</span>?
                  </p>
                  <p className="mt-1 text-sm text-muted-foreground">
                    If that is an exact npm package name, PkgGuard can scan it right now. It takes about 10 to 30 seconds.
                  </p>
                </div>
              </div>
              <Button size="lg" className="h-11 shrink-0 rounded-lg px-5" render={<Link href={packageHref(qName, qVersion)} />} nativeButton={false}>
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

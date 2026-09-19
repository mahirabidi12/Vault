"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowRight, ChevronLeft, ChevronRight, Info, PackageSearch, ScanSearch, Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { VerdictBadge } from "@/components/verdict-ui";
import { usePackageDirectory } from "@/lib/queries";
import { packageHref } from "@/lib/package-ref";
import { formatRelativeTime } from "@/lib/format";
import { verdictStyle } from "@/lib/verdict";
import { cn } from "@/lib/utils";
import type { PackageListParams } from "@/lib/api";

type VerdictFilter = NonNullable<PackageListParams["verdict"]> | "ALL";

const FILTERS: { id: VerdictFilter; label: string }[] = [
  { id: "ALL", label: "All" },
  { id: "SAFE", label: "No issues found" },
  { id: "SUSPICIOUS", label: "Suspicious" },
  { id: "MALICIOUS", label: "Malicious" },
];

const NPM_NAME = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;

function useDebounced<T>(value: T, ms: number): T {
  const [v, setV] = React.useState(value);
  React.useEffect(() => {
    const id = setTimeout(() => setV(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return v;
}

export function PackageDirectory() {
  const router = useRouter();
  const [input, setInput] = React.useState("");
  const [verdict, setVerdict] = React.useState<VerdictFilter>("ALL");
  const q = useDebounced(input.trim(), 300);

  // The page belongs to the search and filter it was picked under, so a new search or filter starts on page 1.
  const filterKey = `${q}|${verdict}`;
  const [picked, setPicked] = React.useState({ key: filterKey, page: 1 });
  const page = picked.key === filterKey ? picked.page : 1;
  const listTop = React.useRef<HTMLDivElement>(null);

  const query = usePackageDirectory({ q, verdict: verdict === "ALL" ? undefined : verdict, page });
  const items = query.data?.items ?? [];
  const partial = query.data?.partial ?? false;
  const total = query.data?.total ?? null;
  const pages = query.data?.pages ?? 1;
  const goTo = (n: number) => {
    setPicked({ key: filterKey, page: n });
    listTop.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const exact = q ? items.some((r) => r.package.name.toLowerCase() === q.toLowerCase()) : true;
  const canScan = q.length > 0 && NPM_NAME.test(q.toLowerCase()) && !query.isFetching && !exact;

  const scan = (e: React.FormEvent) => {
    e.preventDefault();
    if (input.trim() && NPM_NAME.test(input.trim().toLowerCase())) router.push(packageHref(input.trim()));
  };

  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-8 px-4 pb-24 pt-10 sm:px-6 sm:pt-16">
      {/* header */}
      <header className="relative isolate overflow-hidden rounded-3xl border border-white/10 bg-white/[0.02] p-6 sm:p-10">
        <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
          <div className="blob-drift absolute -left-10 -top-24 size-72 rounded-full bg-brand/15 blur-3xl" />
          <div className="blob-drift absolute -bottom-24 right-0 size-64 rounded-full bg-violet-500/10 blur-3xl [animation-delay:-6s]" />
          <div className="bg-grid absolute inset-0 opacity-40 [mask-image:radial-gradient(ellipse_70%_90%_at_20%_20%,black,transparent)]" />
        </div>
        <p className="kicker text-brand">Package directory</p>
        <h1 className="mt-3 max-w-3xl text-balance font-display text-[clamp(2rem,5vw,3.4rem)] font-semibold leading-[1.03] tracking-[-0.04em]">
          Every package we&apos;ve scanned. <span className="text-fade">Or scan a new one.</span>
        </h1>
        <p className="mt-3 max-w-2xl text-[15px] leading-relaxed text-muted-foreground">
          {total !== null ? `${total.toLocaleString()} ${verdict === "ALL" && !q ? "packages" : "matching packages"}. ` : ""}Search the list, open any package to see its full report, or scan one that isn&apos;t here yet.
        </p>

        <form onSubmit={scan} className="mt-7 flex flex-col gap-3 sm:flex-row">
          <div className="relative flex-1">
            <Search className="pointer-events-none absolute left-4 top-1/2 z-10 size-5 -translate-y-1/2 text-muted-foreground" />
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="Search packages, e.g. express or @babel/core"
              aria-label="Search scanned packages"
              className="h-14 w-full rounded-2xl border border-white/12 bg-black/50 pl-12 pr-11 text-base outline-none backdrop-blur transition-colors placeholder:text-muted-foreground/70 focus:border-white/30 focus:ring-4 focus:ring-brand/15"
            />
            {input && (
              <button type="button" onClick={() => setInput("")} aria-label="Clear search" className="absolute right-3 top-1/2 -translate-y-1/2 rounded-md p-1.5 text-muted-foreground hover:bg-white/10 hover:text-foreground">
                <X className="size-4" />
              </button>
            )}
          </div>
          <Button type="submit" size="lg" disabled={!NPM_NAME.test(input.trim().toLowerCase())} className="h-14 rounded-2xl px-6 text-[15px] font-semibold">
            <ScanSearch className="size-5" />
            Scan
          </Button>
        </form>

        <div className="mt-5 flex flex-wrap gap-2" role="group" aria-label="Filter by verdict">
          {FILTERS.map((f) => (
            <button
              key={f.id}
              type="button"
              onClick={() => setVerdict(f.id)}
              aria-pressed={verdict === f.id}
              className={cn(
                "rounded-full border px-4 py-1.5 text-sm transition-all",
                verdict === f.id ? "border-white/40 bg-white/10 font-medium text-foreground" : "border-white/10 text-muted-foreground hover:border-white/25 hover:text-foreground"
              )}
            >
              {f.label}
            </button>
          ))}
        </div>
      </header>

      {partial && (
        <p className="flex items-start gap-3 rounded-2xl border border-suspicious/30 bg-suspicious/[0.07] p-4 text-sm text-foreground/85">
          <Info className="mt-0.5 size-4 shrink-0 text-suspicious" />
          This list is a saved snapshot{query.data?.snapshotAt ? ` from ${new Date(query.data.snapshotAt).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" })}` : ""}, refreshed with recent flagged scans. Packages scanned since may be missing, but you can search or scan any of them.
        </p>
      )}

      {/* scan prompt */}
      {(canScan || (q && items.length === 0 && !query.isFetching)) && (
        <div className="rise-in relative flex flex-col items-start gap-4 overflow-hidden rounded-2xl border border-dashed border-white/20 bg-gradient-to-br from-white/[0.05] to-transparent p-6 sm:flex-row sm:items-center sm:justify-between sm:p-7">
          <div className="flex items-start gap-4">
            <span className="flex size-12 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5">
              <PackageSearch className="size-6" />
            </span>
            <div>
              <p className="text-lg font-semibold">
                {exact ? "Search results" : <>We haven&apos;t scanned <span className="font-mono">{q}</span> yet</>}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">If that is an exact npm package name, PkgGuard can scan it now. It usually takes 20 to 60 seconds.</p>
            </div>
          </div>
          {NPM_NAME.test(q.toLowerCase()) && (
            <Button size="lg" className="h-12 shrink-0 rounded-xl px-6 font-semibold" render={<Link href={packageHref(q)} />} nativeButton={false}>
              <ScanSearch className="size-4" />
              Scan &quot;{q}&quot; now
            </Button>
          )}
        </div>
      )}

      {/* directory */}
      <div ref={listTop} className="-mt-4 scroll-mt-24" />
      {query.isError ? (
        <div className="rounded-2xl border border-malicious/30 bg-malicious/[0.06] p-6 text-sm">
          <p className="font-semibold text-malicious">Couldn&apos;t load the directory</p>
          <p className="mt-1 text-muted-foreground">{query.error instanceof Error ? query.error.message : "Please try again."}</p>
          <Button className="mt-4" onClick={() => query.refetch()}>
            Try again
          </Button>
        </div>
      ) : query.isLoading ? (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {Array.from({ length: 9 }).map((_, i) => (
            <Skeleton key={i} className="h-32 rounded-2xl" />
          ))}
        </div>
      ) : items.length > 0 ? (
        <>
          <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {items.map((r, i) => {
              const style = verdictStyle(r.verdict);
              return (
                <li key={`${r.package.name}@${r.package.version}`} className="rise-in" style={{ animationDelay: `${Math.min(i, 12) * 35}ms` }}>
                  <Link
                    href={packageHref(r.package.name, r.package.version)}
                    className="group relative flex h-full flex-col gap-3 overflow-hidden rounded-2xl border border-white/10 bg-white/[0.025] p-4 pl-5 transition-all duration-300 hover:-translate-y-1 hover:border-white/25 hover:bg-white/[0.05]"
                  >
                    <span aria-hidden className={cn("absolute inset-y-0 left-0 w-1", style.dotClass)} />
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="truncate font-mono text-[15px] font-semibold">{r.package.name}</p>
                        <p className="font-mono text-xs text-muted-foreground">v{r.package.version}</p>
                      </div>
                      <VerdictBadge verdict={r.verdict} size="sm" />
                    </div>
                    {r.summary && <p className="line-clamp-2 text-[13px] leading-snug text-muted-foreground">{r.summary}</p>}
                    <div className="mt-auto flex items-center justify-between text-xs text-muted-foreground/80">
                      <span>{formatRelativeTime(r.analyzedAt)}</span>
                      <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-1 group-hover:text-foreground" />
                    </div>
                  </Link>
                </li>
              );
            })}
          </ul>
          <Pagination page={page} pages={pages} onPage={goTo} busy={query.isFetching} />
        </>
      ) : (
        !q && <p className="py-10 text-center text-sm text-muted-foreground">Nothing to show for this filter.</p>
      )}
    </div>
  );
}

function pageList(page: number, pages: number): (number | "…")[] {
  if (pages <= 7) return Array.from({ length: pages }, (_, i) => i + 1);
  const set = new Set([1, 2, pages - 1, pages, page - 1, page, page + 1]);
  const nums = [...set].filter((n) => n >= 1 && n <= pages).sort((a, b) => a - b);
  const out: (number | "…")[] = [];
  nums.forEach((n, i) => {
    if (i > 0 && n - nums[i - 1] > 1) out.push("…");
    out.push(n);
  });
  return out;
}

function Pagination({ page, pages, onPage, busy }: { page: number; pages: number; onPage: (n: number) => void; busy: boolean }) {
  if (pages <= 1) return null;
  const btn = "flex h-10 min-w-10 items-center justify-center rounded-xl border px-3 text-sm transition-colors";
  return (
    <nav aria-label="Pages" className={cn("flex flex-wrap items-center justify-center gap-2", busy && "opacity-70")}>
      <button type="button" onClick={() => onPage(page - 1)} disabled={page === 1} className={cn(btn, "border-white/10 text-muted-foreground hover:border-white/25 hover:text-foreground disabled:pointer-events-none disabled:opacity-40")} aria-label="Previous page">
        <ChevronLeft className="size-4" />
      </button>
      {pageList(page, pages).map((n, i) =>
        n === "…" ? (
          <span key={`gap-${i}`} className="px-1 text-muted-foreground">…</span>
        ) : (
          <button
            key={n}
            type="button"
            onClick={() => onPage(n)}
            aria-current={n === page ? "page" : undefined}
            aria-label={`Page ${n}`}
            className={cn(btn, n === page ? "border-white/40 bg-white/10 font-semibold text-foreground" : "border-white/10 text-muted-foreground hover:border-white/25 hover:text-foreground")}
          >
            {n}
          </button>
        )
      )}
      <button type="button" onClick={() => onPage(page + 1)} disabled={page === pages} className={cn(btn, "border-white/10 text-muted-foreground hover:border-white/25 hover:text-foreground disabled:pointer-events-none disabled:opacity-40")} aria-label="Next page">
        <ChevronRight className="size-4" />
      </button>
    </nav>
  );
}

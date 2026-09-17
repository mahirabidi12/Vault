import Link from "next/link";
import { getVersions } from "@/lib/api";
import { packageHref } from "@/lib/package-ref";
import { verdictStyle } from "@/lib/verdict";
import { formatRelativeTime } from "@/lib/format";
import { History } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * README §11.3 calls for a version timeline on the report page; it never
 * made it into BRIEF.md's distilled page checklist, so it was missing
 * until now. Only renders when there's actually more than one scanned
 * version — a list of just the version you're already looking at isn't
 * useful.
 */
export async function VersionHistory({ name, currentVersion }: { name: string; currentVersion: string }) {
  const versions = await getVersions(name);
  if (versions.length <= 1) return null;

  const sorted = [...versions].sort((a, b) => (b.analyzedAt ?? b.requestedAt).localeCompare(a.analyzedAt ?? a.requestedAt));

  return (
    <section className="flex flex-col gap-3 rounded-lg border border-border bg-card/60 p-4">
      <span className="kicker flex items-center gap-1.5 text-muted-foreground">
        <History className="size-3.5" />
        {sorted.length} scanned versions
      </span>
      <div className="flex flex-wrap gap-2">
        {sorted.map((v) => {
          const isCurrent = v.package.version === currentVersion;
          const style = verdictStyle(v.verdict);
          return (
            <Link
              key={v.package.version}
              href={packageHref(name, v.package.version)}
              title={`Analyzed ${formatRelativeTime(v.analyzedAt)}`}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 font-mono text-xs transition-colors",
                isCurrent
                  ? "border-brand/40 bg-brand/10 text-foreground"
                  : "border-border bg-background text-muted-foreground hover:border-foreground/30 hover:text-foreground"
              )}
            >
              <span className={cn("size-1.5 rounded-full", style.dotClass)} />
              v{v.package.version}
            </Link>
          );
        })}
      </div>
    </section>
  );
}

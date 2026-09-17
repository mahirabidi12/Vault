import { BookLock, ExternalLink, ShieldCheck, ShieldOff, Terminal } from "lucide-react";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { formatBytes, formatDateTime } from "@/lib/format";
import type { PackageMetadata } from "@/lib/types/domain";

export function PackageInfoCard({ metadata }: { metadata?: PackageMetadata }) {
  if (!metadata) return null;
  const deps = Object.entries(metadata.dependencies ?? {});
  const scripts = Object.entries(metadata.installScripts ?? {});

  return (
    <section className="flex flex-col gap-4 rounded-lg border border-border bg-card/60 p-6">
      <h2 className="font-display text-lg font-semibold tracking-tight">Package info</h2>

      {metadata.description && <p className="text-sm text-foreground/80">{metadata.description}</p>}

      <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm sm:grid-cols-3">
        <Field label="Publisher" value={metadata.publisher ?? "—"} />
        <Field label="License" value={metadata.license ?? "—"} />
        <Field label="Files" value={metadata.fileCount != null ? String(metadata.fileCount) : "—"} />
        <Field label="Unpacked size" value={formatBytes(metadata.unpackedBytes)} />
        <Field label="Published" value={formatDateTime(metadata.publishedAt)} />
        <Field label="Previous version" value={metadata.previousVersion ? `v${metadata.previousVersion}` : "—"} />
      </dl>

      <div className="flex flex-wrap gap-2">
        <TrustChip
          ok={!!metadata.trustedPublishing}
          okLabel="Trusted publishing"
          badLabel="No trusted publishing"
        />
        <TrustChip
          ok={!!metadata.provenance}
          okLabel="Provenance attested"
          badLabel="No provenance"
        />
      </div>

      {metadata.maintainers && metadata.maintainers.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <span className="text-xs font-semibold text-muted-foreground">Maintainers</span>
          <div className="flex flex-wrap gap-1.5">
            {metadata.maintainers.map((m) => (
              <span key={m} className="rounded-full border border-border bg-muted/60 px-2.5 py-0.5 text-xs">
                {m}
              </span>
            ))}
          </div>
        </div>
      )}

      {scripts.length > 0 && (
        <div className="flex flex-col gap-1.5">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-suspicious">
            <Terminal className="size-3.5" />
            Install scripts
          </span>
          <div className="flex flex-col gap-1">
            {scripts.map(([hook, command]) => (
              <div key={hook} className="flex flex-wrap gap-2 rounded-lg border border-suspicious/20 bg-suspicious-bg/60 px-3 py-1.5 font-mono text-xs">
                <span className="font-semibold text-suspicious">{hook}</span>
                <span className="text-foreground/80">{command}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {deps.length > 0 && (
        <Collapsible>
          <CollapsibleTrigger className="flex w-fit items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground">
            <BookLock className="size-3.5" />
            {deps.length} dependenc{deps.length !== 1 ? "ies" : "y"}
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-2 grid grid-cols-2 gap-1.5 sm:grid-cols-3">
            {deps.map(([dep, range]) => (
              <span key={dep} className="truncate rounded-md bg-muted/60 px-2 py-1 font-mono text-[11px] text-muted-foreground">
                {dep}
                <span className="text-muted-foreground/60"> {range}</span>
              </span>
            ))}
          </CollapsibleContent>
        </Collapsible>
      )}

      {metadata.repository && (
        <a
          href={metadata.repository.replace(/^git\+/, "").replace(/\.git$/, "")}
          target="_blank"
          rel="noreferrer"
          className="inline-flex w-fit items-center gap-1.5 text-xs font-medium text-brand hover:underline"
        >
          Repository <ExternalLink className="size-3" />
        </a>
      )}
    </section>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="truncate font-medium">{value}</dd>
    </div>
  );
}

function TrustChip({ ok, okLabel, badLabel }: { ok: boolean; okLabel: string; badLabel: string }) {
  const Icon = ok ? ShieldCheck : ShieldOff;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${
        ok ? "border-safe/25 bg-safe-bg text-safe" : "border-border bg-muted/60 text-muted-foreground"
      }`}
    >
      <Icon className="size-3.5" />
      {ok ? okLabel : badLabel}
    </span>
  );
}

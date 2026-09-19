import {
  BookLock,
  CalendarDays,
  ExternalLink,
  FileCode2,
  GitBranch,
  HardDrive,
  Package,
  Scale,
  ShieldCheck,
  ShieldOff,
  Terminal,
  User,
} from "lucide-react";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { formatBytes, formatDateTime } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { PackageMetadata } from "@/lib/types/domain";

export function PackageInfoCard({ metadata }: { metadata?: PackageMetadata }) {
  if (!metadata) return null;
  const deps = Object.entries(metadata.dependencies ?? {});
  const scripts = Object.entries(metadata.installScripts ?? {});

  return (
    <section className="flex h-full min-w-0 flex-col gap-6 p-5 sm:p-8">
      <header className="flex items-center gap-3">
        <span className="flex size-11 items-center justify-center rounded-xl border border-white/10 bg-white/[0.05]">
          <Package className="size-5" />
        </span>
        <div>
          <h2 className="font-display text-xl font-semibold tracking-tight">Package info</h2>
          <p className="text-sm text-muted-foreground">What the registry says about it</p>
        </div>
      </header>

      {metadata.description && <p className="text-[17px] leading-relaxed text-foreground/90">{metadata.description}</p>}

      <dl className="grid grid-cols-2 gap-3">
        <Fact icon={User} label="Publisher" value={metadata.publisher ?? "—"} />
        <Fact icon={Scale} label="License" value={metadata.license ?? "—"} />
        <Fact icon={FileCode2} label="Files" value={metadata.fileCount != null ? String(metadata.fileCount) : "—"} />
        <Fact icon={HardDrive} label="Unpacked size" value={formatBytes(metadata.unpackedBytes)} />
        <Fact icon={CalendarDays} label="Published" value={formatDateTime(metadata.publishedAt)} />
        <Fact icon={GitBranch} label="Previous version" value={metadata.previousVersion ? `v${metadata.previousVersion}` : "—"} />
      </dl>

      <div className="grid gap-3 sm:grid-cols-2">
        <TrustTile ok={!!metadata.trustedPublishing} title="Trusted publishing" okText="Published from CI" badText="Not used" />
        <TrustTile ok={!!metadata.provenance} title="Provenance" okText="Attested" badText="No attestation" />
      </div>

      {metadata.maintainers && metadata.maintainers.length > 0 && (
        <div className="flex flex-col gap-3">
          <span className="text-sm font-semibold text-muted-foreground">Maintainers</span>
          <div className="flex flex-wrap gap-2">
            {metadata.maintainers.map((m) => (
              <span
                key={m}
                className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.04] py-1 pl-1 pr-3.5 text-[15px] transition-colors hover:border-white/25 hover:bg-white/[0.08]"
              >
                <Avatar name={m} />
                {m}
              </span>
            ))}
          </div>
        </div>
      )}

      {scripts.length > 0 && (
        <div className="flex flex-col gap-2.5">
          <span className="inline-flex items-center gap-2 text-sm font-semibold text-suspicious">
            <Terminal className="size-4" />
            Install scripts
          </span>
          {scripts.map(([hook, command]) => (
            <div key={hook} className="flex flex-wrap gap-x-3 gap-y-1 rounded-xl border border-suspicious/25 bg-suspicious-bg/60 px-4 py-3 font-mono text-sm">
              <span className="font-semibold text-suspicious">{hook}</span>
              <span className="text-foreground/80">{command}</span>
            </div>
          ))}
        </div>
      )}

      <div className="mt-auto flex flex-wrap items-center gap-3 border-t border-white/10 pt-5">
        {deps.length > 0 && (
          <Collapsible className="w-full">
            <CollapsibleTrigger className="group inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.04] px-3.5 py-2 text-sm font-medium transition-colors hover:bg-white/[0.08]">
              <BookLock className="size-4 text-muted-foreground" />
              {deps.length} dependenc{deps.length !== 1 ? "ies" : "y"}
              <span className="text-xs text-muted-foreground group-data-[panel-open]:hidden">show</span>
              <span className="hidden text-xs text-muted-foreground group-data-[panel-open]:inline">hide</span>
            </CollapsibleTrigger>
            <CollapsibleContent className="mt-3 grid grid-cols-2 gap-2 sm:grid-cols-3">
              {deps.map(([dep, range]) => (
                <span key={dep} className="truncate rounded-lg border border-white/8 bg-white/[0.03] px-2.5 py-1.5 font-mono text-xs text-foreground/85">
                  {dep}
                  <span className="text-muted-foreground/70"> {range}</span>
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
            className="inline-flex items-center gap-2 rounded-lg bg-foreground px-4 py-2 text-sm font-semibold text-background transition-opacity hover:opacity-90"
          >
            View repository <ExternalLink className="size-3.5" />
          </a>
        )}
      </div>
    </section>
  );
}

function Fact({ icon: Icon, label, value }: { icon: typeof User; label: string; value: string }) {
  return (
    <div className="group flex min-w-0 flex-col gap-2 rounded-2xl border border-white/10 bg-white/[0.03] p-3.5 transition-all sm:p-4 duration-300 hover:-translate-y-0.5 hover:border-white/25 hover:bg-white/[0.06]">
      <dt className="flex items-center gap-2 text-[13px] text-muted-foreground">
        <Icon className="size-4 transition-colors group-hover:text-foreground" />
        {label}
      </dt>
      <dd className="truncate text-base font-semibold tracking-tight sm:text-lg">{value}</dd>
    </div>
  );
}

function TrustTile({ ok, title, okText, badText }: { ok: boolean; title: string; okText: string; badText: string }) {
  const Icon = ok ? ShieldCheck : ShieldOff;
  return (
    <div
      className={cn(
        "flex items-center gap-3 rounded-2xl border p-4",
        ok ? "border-safe/30 bg-safe-bg/60" : "border-white/10 bg-white/[0.03]"
      )}
    >
      <span
        className={cn(
          "flex size-10 shrink-0 items-center justify-center rounded-xl border",
          ok ? "border-safe/40 bg-safe/10 text-safe" : "border-white/10 bg-white/5 text-muted-foreground"
        )}
      >
        <Icon className="size-5" />
      </span>
      <div className="min-w-0">
        <p className="text-[13px] text-muted-foreground">{title}</p>
        <p className={cn("text-base font-semibold", ok ? "text-safe" : "text-foreground")}>{ok ? okText : badText}</p>
      </div>
    </div>
  );
}

function Avatar({ name }: { name: string }) {
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return (
    <span
      aria-hidden
      className="flex size-7 items-center justify-center rounded-full text-xs font-bold uppercase text-black"
      style={{ background: `hsl(${h} 70% 68%)` }}
    >
      {name.slice(0, 1)}
    </span>
  );
}

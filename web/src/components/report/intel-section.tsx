import { Radar, ShieldAlert, ShieldCheck, CircleAlert, UserCheck, Database } from "lucide-react";
import { cn } from "@/lib/utils";
import type { IntelResult } from "@/lib/types/domain";

export function IntelSection({ intel }: { intel?: IntelResult }) {
  if (!intel || (!intel.osv && !intel.safedep)) return null;

  const osv = intel.osv;
  const sd = intel.safedep;

  return (
    <section className="flex flex-col gap-6 p-6 sm:p-8">
      <header className="flex items-center gap-3">
        <span className="flex size-11 items-center justify-center rounded-xl border border-white/10 bg-white/[0.05]">
          <Radar className="size-5" />
        </span>
        <div>
          <h2 className="font-display text-xl font-semibold tracking-tight">Threat intelligence</h2>
          <p className="text-sm text-muted-foreground">Two public malware databases, checked live</p>
        </div>
      </header>

      <div className="grid gap-3 sm:grid-cols-2">
        {osv && (
          <SourceTile name="OSV.dev" sub="Open-source vulnerability and malware advisories">
            {osv.error ? (
              <Status tone="muted" icon={CircleAlert} text="Lookup failed" note={osv.error} />
            ) : osv.maliciousIds.length > 0 ? (
              <Status tone="bad" icon={ShieldAlert} text="Known malware" note={osv.maliciousIds.join(", ")} />
            ) : (
              <Status tone="ok" icon={ShieldCheck} text="No malware advisory" />
            )}
            {osv.vulnerabilityIds.length > 0 && (
              <p className="text-sm text-muted-foreground">
                {osv.vulnerabilityIds.length} known vulnerabilit{osv.vulnerabilityIds.length !== 1 ? "ies" : "y"}:{" "}
                <span className="font-mono">{osv.vulnerabilityIds.join(", ")}</span>
              </p>
            )}
          </SourceTile>
        )}

        {sd && (
          <SourceTile name="SafeDep" sub="Community malware analysis feed">
            {sd.error ? (
              <Status tone="muted" icon={CircleAlert} text="Lookup failed" note={sd.error} />
            ) : !sd.found ? (
              <Status tone="muted" icon={ShieldCheck} text="Not analyzed" />
            ) : sd.isMalware ? (
              <Status tone="bad" icon={ShieldAlert} text="Flagged as malware" />
            ) : (
              <Status tone="ok" icon={ShieldCheck} text="No malware flag" />
            )}
            {sd.confidence && <ConfidenceBars level={sd.confidence.replace("CONFIDENCE_", "")} />}
            {sd.humanVerified && (
              <span className="inline-flex items-center gap-1.5 text-sm text-safe">
                <UserCheck className="size-4" /> Human verified
              </span>
            )}
          </SourceTile>
        )}
      </div>
    </section>
  );
}

function SourceTile({ name, sub, children }: { name: string; sub: string; children: React.ReactNode }) {
  return (
    <div className="group flex flex-col gap-4 rounded-2xl border border-white/10 bg-white/[0.03] p-5 transition-all duration-300 hover:-translate-y-0.5 hover:border-white/25 hover:bg-white/[0.06]">
      <div className="flex items-center gap-2.5">
        <span className="flex size-8 items-center justify-center rounded-lg border border-white/10 bg-white/5">
          <Database className="size-4 text-muted-foreground" />
        </span>
        <div className="min-w-0">
          <p className="text-[15px] font-semibold leading-tight">{name}</p>
          <p className="truncate text-xs text-muted-foreground">{sub}</p>
        </div>
      </div>
      {children}
    </div>
  );
}

function Status({
  tone,
  icon: Icon,
  text,
  note,
}: {
  tone: "ok" | "bad" | "muted";
  icon: typeof ShieldCheck;
  text: string;
  note?: string;
}) {
  const color = tone === "ok" ? "text-safe" : tone === "bad" ? "text-malicious" : "text-muted-foreground";
  const ring = tone === "ok" ? "border-safe/40 bg-safe/10" : tone === "bad" ? "border-malicious/40 bg-malicious/10" : "border-white/15 bg-white/5";
  return (
    <div className="flex items-center gap-3">
      <span className={cn("relative flex size-11 shrink-0 items-center justify-center rounded-full border", ring, color)}>
        {tone === "ok" && <span aria-hidden className="ping-ring absolute inset-0 rounded-full border border-safe/40" />}
        <Icon className="size-5" />
      </span>
      <div className="min-w-0">
        <p className={cn("text-lg font-semibold leading-tight", color)}>{text}</p>
        {note && <p className="break-all font-mono text-xs text-muted-foreground">{note}</p>}
      </div>
    </div>
  );
}

function ConfidenceBars({ level }: { level: string }) {
  const n = level === "HIGH" ? 3 : level === "MEDIUM" ? 2 : 1;
  return (
    <div className="flex items-center gap-2.5 text-sm text-muted-foreground">
      <span className="flex items-end gap-1" aria-hidden>
        {[1, 2, 3].map((i) => (
          <span key={i} className={cn("w-1.5 rounded-full", i <= n ? "bg-safe" : "bg-white/15")} style={{ height: 6 + i * 4 }} />
        ))}
      </span>
      {level.toLowerCase()} confidence
    </div>
  );
}

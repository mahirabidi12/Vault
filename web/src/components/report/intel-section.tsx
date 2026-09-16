import { Radar, ShieldAlert, ShieldCheck, CircleAlert, UserCheck } from "lucide-react";
import type { IntelResult } from "@/lib/types/domain";

export function IntelSection({ intel }: { intel?: IntelResult }) {
  if (!intel || (!intel.osv && !intel.safedep)) return null;

  return (
    <section className="flex flex-col gap-4 rounded-2xl border border-border bg-card/60 p-6">
      <h2 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
        <Radar className="size-4.5" />
        Threat intelligence
      </h2>

      <div className="grid gap-4 sm:grid-cols-2">
        {intel.osv && (
          <div className="flex flex-col gap-2 rounded-xl border border-border/70 bg-background/50 p-4">
            <span className="text-xs font-semibold text-muted-foreground">OSV.dev</span>
            {intel.osv.error ? (
              <ErrorRow message={intel.osv.error} />
            ) : intel.osv.maliciousIds.length > 0 ? (
              <StatusRow icon={ShieldAlert} tone="malicious" text={`Known malware: ${intel.osv.maliciousIds.join(", ")}`} />
            ) : (
              <StatusRow icon={ShieldCheck} tone="safe" text="No malicious-package advisory" />
            )}
            {intel.osv.vulnerabilityIds.length > 0 && (
              <p className="text-xs text-muted-foreground">
                {intel.osv.vulnerabilityIds.length} known vulnerabilit
                {intel.osv.vulnerabilityIds.length !== 1 ? "ies" : "y"}: {intel.osv.vulnerabilityIds.join(", ")}
              </p>
            )}
          </div>
        )}

        {intel.safedep && (
          <div className="flex flex-col gap-2 rounded-xl border border-border/70 bg-background/50 p-4">
            <span className="text-xs font-semibold text-muted-foreground">SafeDep</span>
            {intel.safedep.error ? (
              <ErrorRow message={intel.safedep.error} />
            ) : !intel.safedep.found ? (
              <StatusRow icon={ShieldCheck} tone="muted" text="Not analyzed by SafeDep" />
            ) : intel.safedep.isMalware ? (
              <StatusRow icon={ShieldAlert} tone="malicious" text="Flagged as malware" />
            ) : (
              <StatusRow icon={ShieldCheck} tone="safe" text="No malware flag" />
            )}
            <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
              {intel.safedep.confidence && <span>{intel.safedep.confidence.replace("CONFIDENCE_", "").toLowerCase()} confidence</span>}
              {intel.safedep.humanVerified && (
                <span className="inline-flex items-center gap-1 text-safe">
                  <UserCheck className="size-3" /> Human verified
                </span>
              )}
            </div>
          </div>
        )}
      </div>
    </section>
  );
}

function StatusRow({
  icon: Icon,
  tone,
  text,
}: {
  icon: typeof ShieldCheck;
  tone: "safe" | "malicious" | "muted";
  text: string;
}) {
  const toneClass = tone === "safe" ? "text-safe" : tone === "malicious" ? "text-malicious" : "text-muted-foreground";
  return (
    <span className={`inline-flex items-center gap-2 text-sm font-medium ${toneClass}`}>
      <Icon className="size-4" />
      {text}
    </span>
  );
}

function ErrorRow({ message }: { message: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm font-medium text-muted-foreground">
      <CircleAlert className="size-4" />
      Lookup failed: {message}
    </span>
  );
}

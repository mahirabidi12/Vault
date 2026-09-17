import { XCircle, MinusCircle } from "lucide-react";
import type { VerdictRecord } from "@/lib/types/domain";

export function ScanFailedState({ record }: { record: VerdictRecord }) {
  const skipped = record.status === "SKIPPED";
  const Icon = skipped ? MinusCircle : XCircle;

  return (
    <div className="mx-auto flex max-w-lg flex-col items-center gap-4 px-4 py-24 text-center">
      <Icon className={skipped ? "size-10 text-muted-foreground" : "size-10 text-malicious"} />
      <h1 className="font-display text-xl font-semibold tracking-tight">
        {skipped ? "Scan skipped" : "Scan failed"}
      </h1>
      <p className="font-mono text-sm">
        {record.package.name}@{record.package.version}
      </p>
      <p className="max-w-sm text-sm text-muted-foreground">
        {record.failureReason ?? (skipped ? "This package couldn't be scanned." : "Something went wrong while scanning this package.")}
      </p>
      <p className="text-xs text-muted-foreground/70">
        {skipped
          ? "PkgGuard didn't produce a verdict, so treat this package with extra caution."
          : "No verdict was produced. Try again later, or treat this package with extra caution."}
      </p>
    </div>
  );
}

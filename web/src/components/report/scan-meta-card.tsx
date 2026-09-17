import { formatDateTime } from "@/lib/format";
import type { CodeScanSummary } from "@/lib/types/domain";
import type { VerdictRecord } from "@/lib/types/domain";
import { Cpu, ScanSearch } from "lucide-react";

export function ScanMetaCard({
  record,
  codeScan,
}: {
  record: VerdictRecord;
  codeScan?: CodeScanSummary;
}) {
  return (
    <section className="flex flex-col gap-4 rounded-lg border border-border bg-card/60 p-6">
      <h2 className="flex items-center gap-2 font-display text-lg font-semibold tracking-tight">
        <Cpu className="size-4.5" />
        Scan details
      </h2>
      <dl className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
        <Field label="Analyzer version" value={record.analyzerVersion} />
        <Field label="Ran on" value={record.ranOn === "cloud" ? "AWS cloud" : "Local"} />
        <Field label="Model" value={record.model ?? "None (rules only)"} />
        <Field label="Requested" value={formatDateTime(record.requestedAt)} />
        <Field label="Analyzed" value={formatDateTime(record.analyzedAt)} />
        <Field label="Scan ID" value={record.scanId} mono />
      </dl>

      {codeScan && (
        <div className="flex flex-col gap-2 border-t border-border/60 pt-4">
          <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
            <ScanSearch className="size-3.5" />
            Code scan
          </span>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-3">
            <Field label="Files scanned" value={String(codeScan.filesScanned ?? 0)} />
            <Field label="Files parsed" value={String(codeScan.filesParsed ?? 0)} />
            <Field label="Entry files" value={String(codeScan.entryFiles?.length ?? 0)} />
            <Field label="Install-time files" value={String(codeScan.installTimeFiles?.length ?? 0)} />
            <Field label="Executables" value={String(codeScan.executables?.length ?? 0)} />
            <Field label="Findings truncated" value={codeScan.findingsTruncated ? "Yes" : "No"} />
          </dl>
        </div>
      )}
    </section>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className={`truncate font-medium ${mono ? "font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}

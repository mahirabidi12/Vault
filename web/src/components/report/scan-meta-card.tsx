import { formatDateTime } from "@/lib/format";
import { CopyButton } from "@/components/copy-button";
import { CountUp } from "@/components/count-up";
import type { CodeScanSummary, VerdictRecord } from "@/lib/types/domain";
import { Bot, Cloud, Cpu, Hash, ScanSearch, Timer, Cog } from "lucide-react";

const num = (v: unknown) => (typeof v === "number" ? v : 0);
const len = (v: unknown) => (Array.isArray(v) ? v.length : 0);

export function ScanMetaCard({ record, codeScan }: { record: VerdictRecord; codeScan?: CodeScanSummary }) {
  const took =
    record.analyzedAt && record.requestedAt
      ? Math.max(0, Math.round((Date.parse(record.analyzedAt) - Date.parse(record.requestedAt)) / 1000))
      : null;
  const scanned = num(codeScan?.filesScanned);
  const parsed = num(codeScan?.filesParsed);

  return (
    <section className="flex flex-col gap-6 p-6 sm:p-8">
      <header className="flex items-center gap-3">
        <span className="flex size-11 items-center justify-center rounded-xl border border-white/10 bg-white/[0.05]">
          <Cpu className="size-5" />
        </span>
        <div>
          <h2 className="font-display text-xl font-semibold tracking-tight">Scan details</h2>
          <p className="text-sm text-muted-foreground">Exactly what ran, and when</p>
        </div>
      </header>

      <div className="grid grid-cols-2 gap-3">
        <Tile icon={Timer} label="Scan took" value={took != null ? <><CountUp value={took} /> s</> : "—"} />
        <Tile icon={record.ranOn === "cloud" ? Cloud : Cog} label="Ran on" value={record.ranOn === "cloud" ? "AWS cloud" : "Local"} />
        <Tile icon={Bot} label="AI model" value={record.model ? (record.model.split(".").pop() ?? record.model) : "None"} sub={record.model ? undefined : "rules only"} />
        <Tile icon={Cog} label="Analyzer" value={`v${record.analyzerVersion}`} />
      </div>

      <div className="grid gap-x-6 gap-y-3 text-[15px] sm:grid-cols-2">
        <Line label="Requested" value={formatDateTime(record.requestedAt)} />
        <Line label="Analyzed" value={formatDateTime(record.analyzedAt)} />
      </div>

      <div className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-black/40 px-4 py-3">
        <span className="flex items-center gap-2 text-sm text-muted-foreground">
          <Hash className="size-4" /> Scan ID
        </span>
        <CopyButton value={record.scanId} label={record.scanId} className="h-auto px-0 py-0 text-sm text-foreground hover:bg-transparent" />
      </div>

      {codeScan && (
        <div className="flex flex-col gap-4 border-t border-white/10 pt-6">
          <span className="inline-flex items-center gap-2 text-sm font-semibold text-muted-foreground">
            <ScanSearch className="size-4" />
            Code scan
          </span>

          <div className="flex flex-col gap-2">
            <div className="flex items-baseline justify-between text-sm">
              <span className="text-muted-foreground">Files parsed</span>
              <span className="font-semibold">
                {parsed} <span className="font-normal text-muted-foreground">of {scanned} scanned</span>
              </span>
            </div>
            <div className="h-2 overflow-hidden rounded-full bg-white/10">
              <div
                className="line-grow h-full rounded-full bg-gradient-to-r from-white/40 to-white"
                style={{ width: `${scanned > 0 ? Math.round((parsed / scanned) * 100) : 0}%` }}
              />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Mini label="Entry files" value={len(codeScan.entryFiles)} />
            <Mini label="Install-time" value={len(codeScan.installTimeFiles)} />
            <Mini label="Executables" value={len(codeScan.executables)} />
            <Mini label="Truncated" text={codeScan.findingsTruncated ? "Yes" : "No"} />
          </div>
        </div>
      )}
    </section>
  );
}

function Tile({ icon: Icon, label, value, sub }: { icon: typeof Cpu; label: string; value: React.ReactNode; sub?: string }) {
  return (
    <div className="group flex flex-col gap-2 rounded-2xl border border-white/10 bg-white/[0.03] p-4 transition-all duration-300 hover:-translate-y-0.5 hover:border-white/25 hover:bg-white/[0.06]">
      <span className="flex items-center gap-2 text-[13px] text-muted-foreground">
        <Icon className="size-4 transition-colors group-hover:text-foreground" />
        {label}
      </span>
      <span className="truncate text-xl font-semibold tracking-tight">{value}</span>
      {sub && <span className="-mt-1 text-xs text-muted-foreground">{sub}</span>}
    </div>
  );
}

function Line({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[13px] text-muted-foreground">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}

function Mini({ label, value, text }: { label: string; value?: number; text?: string }) {
  return (
    <div className="rounded-xl border border-white/10 bg-white/[0.03] px-3 py-2.5">
      <p className="text-2xl font-semibold tracking-tight">{text ?? value}</p>
      <p className="text-xs text-muted-foreground">{label}</p>
    </div>
  );
}

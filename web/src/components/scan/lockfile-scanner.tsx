"use client";

import * as React from "react";
import Link from "next/link";
import { useCheckPackages } from "@/lib/queries";
import { parsePackageLock, EXAMPLE_LOCKFILE } from "@/lib/lockfile";
import { packageHref } from "@/lib/package-ref";
import { VerdictBadge, StatusBadge } from "@/components/verdict-ui";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import type { PackageRef, VerdictRecord } from "@/lib/types/domain";
import { UploadCloud, FileJson, Sparkles, ShieldCheck, ShieldAlert, ShieldX, Loader2 } from "lucide-react";
import { toast } from "sonner";

function rank(r: VerdictRecord): number {
  if (r.status === "PENDING" || r.status === "SCANNING") return 0;
  if (r.verdict === "MALICIOUS") return 1;
  if (r.verdict === "SUSPICIOUS") return 2;
  if (r.status === "FAILED" || r.status === "SKIPPED") return 3;
  return 4;
}

export function LockfileScanner() {
  const [refs, setRefs] = React.useState<PackageRef[] | null>(null);
  const [dragOver, setDragOver] = React.useState(false);
  const inputRef = React.useRef<HTMLInputElement>(null);

  const { data: results, isFetching } = useCheckPackages(refs ?? []);

  function loadText(text: string, sourceName: string) {
    try {
      const parsed = parsePackageLock(text);
      if (parsed.length === 0) {
        toast.error("No dependencies found in that lockfile.");
        return;
      }
      setRefs(parsed);
      toast.success(`Parsed ${parsed.length} packages from ${sourceName}.`);
    } catch {
      toast.error("Couldn't parse that as a package-lock.json.");
    }
  }

  function onFile(file: File) {
    file.text().then((text) => loadText(text, file.name));
  }

  const total = refs?.length ?? 0;
  const done = results?.filter((r) => r.status !== "PENDING" && r.status !== "SCANNING").length ?? 0;
  const sorted = results ? [...results].sort((a, b) => rank(a) - rank(b)) : [];
  const counts = {
    malicious: results?.filter((r) => r.verdict === "MALICIOUS").length ?? 0,
    suspicious: results?.filter((r) => r.verdict === "SUSPICIOUS").length ?? 0,
    safe: results?.filter((r) => r.verdict === "SAFE").length ?? 0,
  };

  return (
    <div className="flex flex-col gap-6">
      {!refs && (
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragOver(true);
          }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragOver(false);
            const file = e.dataTransfer.files?.[0];
            if (file) onFile(file);
          }}
          className={`flex flex-col items-center gap-4 rounded-2xl border-2 border-dashed p-10 text-center transition-colors ${
            dragOver ? "border-brand bg-brand/5" : "border-border bg-card/40"
          }`}
        >
          <span className="flex size-12 items-center justify-center rounded-full bg-brand/10 text-brand">
            <UploadCloud className="size-6" />
          </span>
          <div className="flex flex-col gap-1">
            <p className="font-medium">Drop your package-lock.json here</p>
            <p className="text-sm text-muted-foreground">or click to browse. Nothing leaves your browser.</p>
          </div>
          <div className="flex flex-wrap items-center justify-center gap-2">
            <Button onClick={() => inputRef.current?.click()}>
              <FileJson className="size-4" />
              Choose file
            </Button>
            <Button variant="outline" onClick={() => loadText(EXAMPLE_LOCKFILE, "the example project")}>
              <Sparkles className="size-4" />
              Try an example
            </Button>
          </div>
          <input
            ref={inputRef}
            type="file"
            accept="application/json,.json"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) onFile(file);
            }}
          />
        </div>
      )}

      {refs && (
        <>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-col gap-1">
              <p className="text-sm font-medium">
                {done} / {total} checked
                {isFetching && done < total && <Loader2 className="ml-2 inline size-3.5 animate-spin text-muted-foreground" />}
              </p>
              <Progress value={total ? (done / total) * 100 : 0} className="h-1.5 w-56" />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <SummaryChip icon={ShieldX} tone="malicious" count={counts.malicious} label="malicious" />
              <SummaryChip icon={ShieldAlert} tone="suspicious" count={counts.suspicious} label="suspicious" />
              <SummaryChip icon={ShieldCheck} tone="safe" count={counts.safe} label="clean" />
              <Button variant="ghost" size="sm" onClick={() => setRefs(null)}>
                Scan another
              </Button>
            </div>
          </div>

          <div className="flex flex-col gap-2">
            {sorted.map((record) => (
              <Link
                key={`${record.package.name}@${record.package.version}`}
                href={packageHref(record.package.name, record.package.version)}
                className="flex items-center justify-between gap-3 rounded-xl border border-border bg-card/50 px-4 py-3 transition-colors hover:border-brand/40 hover:bg-accent/20"
              >
                <span className="truncate font-mono text-sm">
                  {record.package.name}
                  <span className="text-muted-foreground">@{record.package.version}</span>
                </span>
                {record.status === "COMPLETE" ? (
                  <VerdictBadge verdict={record.verdict} size="sm" />
                ) : (
                  <StatusBadge status={record.status} />
                )}
              </Link>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function SummaryChip({
  icon: Icon,
  tone,
  count,
  label,
}: {
  icon: typeof ShieldCheck;
  tone: "malicious" | "suspicious" | "safe";
  count: number;
  label: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium ${
        tone === "malicious"
          ? "border-malicious/25 bg-malicious-bg text-malicious"
          : tone === "suspicious"
            ? "border-suspicious/25 bg-suspicious-bg text-suspicious"
            : "border-safe/25 bg-safe-bg text-safe"
      }`}
    >
      <Icon className="size-3.5" />
      {count} {label}
    </span>
  );
}

import type { Metadata } from "next";
import { LockfileScanner } from "@/components/scan/lockfile-scanner";
import { ShieldCheck } from "lucide-react";

export const metadata: Metadata = { title: "Scan a project" };

export default function ScanPage() {
  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-8 px-4 py-10 sm:px-6">
      <div className="flex flex-col gap-2">
        <span className="inline-flex w-fit items-center gap-1.5 rounded-full border border-border bg-card/60 px-3 py-1.5 text-muted-foreground kicker">
          <ShieldCheck className="size-3.5" />
          Whole-project scan
        </span>
        <h1 className="font-display text-2xl font-semibold tracking-tight">Scan a project</h1>
        <p className="text-sm text-muted-foreground">
          Upload a <code className="rounded bg-muted px-1 py-0.5 text-xs">package-lock.json</code> to see a
          verdict for every dependency, malicious and suspicious first. Parsing happens entirely in your
          browser — the file is never uploaded anywhere.
        </p>
      </div>
      <LockfileScanner />
    </div>
  );
}

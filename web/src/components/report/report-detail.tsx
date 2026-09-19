import { VerdictHero } from "@/components/report/verdict-hero";
import { SignalsRow } from "@/components/report/signals-row";
import { FindingsSection } from "@/components/report/findings-section";
import { AiReviewSection } from "@/components/report/ai-review-section";
import { PackageInfoCard } from "@/components/report/package-info-card";
import { IntelSection } from "@/components/report/intel-section";
import { ScanMetaCard } from "@/components/report/scan-meta-card";
import { VersionHistory } from "@/components/report/version-history";
import { StatTiles, type Stat } from "@/components/report/stat-tiles";
import { PipelineTrace, type TraceStage } from "@/components/report/pipeline-trace";
import { DynamicAnalysis } from "@/components/report/dynamic-analysis";
import { sandboxStage } from "@/lib/sandbox";
import { Reveal } from "@/components/reveal";
import { SpotlightCard } from "@/components/spotlight-card";
import { verdictStyle, DECIDED_BY_LABEL } from "@/lib/verdict";
import type { Report, VerdictRecord } from "@/lib/types/domain";

const num = (v: unknown) => (typeof v === "number" ? v : 0);

function traceStages(record: VerdictRecord, report: Report): TraceStage[] {
  const findings = report.findings ?? [];
  const count = (layer: string) => findings.filter((f) => f.layer === layer).length;
  const osvMal = report.intel?.osv?.maliciousIds?.length ?? 0;
  const sdMal = report.intel?.safedep?.isMalware;
  const meta = count("metadata");
  const code = count("static");
  const files = num(report.codeScan?.filesScanned);
  const ai = report.aiReview;
  const vs = verdictStyle(record.verdict);
  const verdictTone = record.verdict === "MALICIOUS" ? "bad" : record.verdict === "SUSPICIOUS" ? "warn" : "ok";

  return [
    {
      key: "intel",
      title: "Threat intel",
      headline: osvMal > 0 || sdMal ? "Known malware" : "No match",
      detail: "OSV.dev and SafeDep",
      tone: osvMal > 0 || sdMal ? "bad" : "ok",
    },
    {
      key: "info",
      title: "Package info",
      headline: meta > 0 ? `${meta} flag${meta !== 1 ? "s" : ""}` : "Nothing odd",
      detail: report.metadata?.trustedPublishing ? "Trusted publishing" : "Scripts, publisher, age",
      tone: meta > 1 ? "warn" : meta === 1 ? "warn" : "ok",
    },
    {
      key: "static",
      title: "Static scan",
      headline: code > 0 ? `${code} finding${code !== 1 ? "s" : ""}` : "Clean",
      detail: files > 0 ? `${files.toLocaleString()} files read as text` : "Code read as text",
      tone: code > 0 ? "warn" : "ok",
    },
    {
      key: "sandbox",
      title: "Sandbox",
      ...sandboxStage(report.sandbox),
    },
    {
      key: "ai",
      title: "AI review",
      headline: ai ? verdictStyle(ai.verdict).shortLabel : record.aiFailed ? "Unavailable" : "Not run",
      detail: ai ? `${ai.model?.split(".").pop() ?? "model"} · ${ai.toolCalls ?? 0} tool calls` : "Rules only",
      tone: ai ? (ai.verdict === "MALICIOUS" ? "bad" : ai.verdict === "SUSPICIOUS" ? "warn" : "ok") : "muted",
    },
    {
      key: "verdict",
      title: "Verdict",
      headline: vs.shortLabel,
      detail: record.decidedBy ? `Decided by ${DECIDED_BY_LABEL[record.decidedBy].toLowerCase()}` : "Final call",
      tone: verdictTone,
    },
  ];
}

function statTiles(record: VerdictRecord, report: Report): Stat[] {
  const findings = report.findings ?? [];
  const high = findings.filter((f) => f.severity === "HIGH").length;
  return [
    { label: "Files scanned", value: num(report.codeScan?.filesScanned), icon: "files" },
    { label: "Findings", value: findings.length, icon: "findings", tone: high > 0 ? "bad" : findings.length > 0 ? "warn" : undefined },
    { label: "Install-time files", value: Array.isArray(report.codeScan?.installTimeFiles) ? (report.codeScan!.installTimeFiles as unknown[]).length : 0, icon: "install" },
    { label: "Unpacked size", value: Math.round((report.metadata?.unpackedBytes ?? 0) / 1024), suffix: "KB", icon: "size" },
  ];
}

export async function ReportDetail({
  record,
  report,
}: {
  record: VerdictRecord;
  report: Report;
}) {
  return (
    <div className="mx-auto flex max-w-6xl flex-col gap-10 px-4 pb-8 pt-8 sm:px-6 sm:pt-12">
      <VerdictHero record={record} evaluationSample={report.metadata?.evaluationSample === true} />
      <StatTiles stats={statTiles(record, report)} />
      <Reveal>
        <PipelineTrace stages={traceStages(record, report)} />
      </Reveal>
      <Reveal>
        <DynamicAnalysis sandbox={report.sandbox} record={record} />
      </Reveal>
      <VersionHistory name={record.package.name} currentVersion={record.package.version} />
      <SignalsRow signals={record.signals} />
      <Reveal>
        <FindingsSection findings={report.findings ?? []} />
      </Reveal>
      <Reveal>
        <AiReviewSection
          aiReview={report.aiReview}
          aiError={report.aiError}
          aiFailed={record.aiFailed}
          finalVerdict={record.verdict}
        />
      </Reveal>
      <div className="grid gap-6 lg:grid-cols-2">
        <Reveal className="min-w-0">
          <SpotlightCard className="h-full">
            <PackageInfoCard metadata={report.metadata} />
          </SpotlightCard>
        </Reveal>
        <div className="flex min-w-0 flex-col gap-6">
          <Reveal delay={100}>
            <SpotlightCard>
              <IntelSection intel={report.intel} evaluationNote={report.metadata?.evaluationSample ? report.metadata.intelLookup : undefined} />
            </SpotlightCard>
          </Reveal>
          <Reveal delay={200}>
            <SpotlightCard>
              <ScanMetaCard record={record} codeScan={report.codeScan} />
            </SpotlightCard>
          </Reveal>
        </div>
      </div>
    </div>
  );
}

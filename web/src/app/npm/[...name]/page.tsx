import type { Metadata } from "next";
import { getPackage, getReport, isNotFoundError } from "@/lib/api";
import { segmentsToName } from "@/lib/package-ref";
import { ReportDetail } from "@/components/report/report-detail";
import { LiveScanProgress } from "@/components/report/live-scan-progress";
import { ScanFailedState } from "@/components/report/scan-failed-state";
import { ScanAutoRefresh } from "@/components/report/scan-auto-refresh";
import { PackageNotFound } from "@/components/report/package-not-found";

type Props = {
  params: Promise<{ name: string[] }>;
  searchParams: Promise<{ version?: string }>;
};

export async function generateMetadata({ params, searchParams }: Props): Promise<Metadata> {
  const { name: segments } = await params;
  const { version } = await searchParams;
  const name = segmentsToName(segments);
  let record;
  try {
    record = await getPackage(name, version);
  } catch (error) {
    if (isNotFoundError(error)) {
      return { title: `${name} — not found`, description: `There's no npm package named ${name}.` };
    }
    throw error;
  }
  const verdictLabel =
    record.status === "COMPLETE"
      ? record.verdict === "SAFE"
        ? "No issues found"
        : record.verdict
      : record.status;
  return {
    title: `${name}@${record.package.version} — ${verdictLabel}`,
    description: record.summary ?? `PkgGuard scan report for ${name}.`,
  };
}

export default async function PackageReportPage({ params, searchParams }: Props) {
  const { name: segments } = await params;
  const { version } = await searchParams;
  const name = segmentsToName(segments);

  let record;
  try {
    record = await getPackage(name, version);
  } catch (error) {
    if (isNotFoundError(error)) {
      return <PackageNotFound name={name} version={version} />;
    }
    throw error;
  }

  if (record.status === "PENDING" || record.status === "SCANNING") {
    return (
      <>
        <ScanAutoRefresh status={record.status} />
        <LiveScanProgress record={record} />
      </>
    );
  }

  if (record.status === "FAILED" || record.status === "SKIPPED") {
    return <ScanFailedState record={record} />;
  }

  const report = await getReport(record.package.name, record.package.version);
  if (!report) {
    return <ScanFailedState record={{ ...record, status: "FAILED", failureReason: "Report unavailable." }} />;
  }

  return <ReportDetail record={record} report={report} />;
}

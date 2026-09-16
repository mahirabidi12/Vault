import { VerdictHero } from "@/components/report/verdict-hero";
import { SignalsRow } from "@/components/report/signals-row";
import { FindingsSection } from "@/components/report/findings-section";
import { AiReviewSection } from "@/components/report/ai-review-section";
import { PackageInfoCard } from "@/components/report/package-info-card";
import { IntelSection } from "@/components/report/intel-section";
import { ScanMetaCard } from "@/components/report/scan-meta-card";
import type { Report, VerdictRecord } from "@/lib/types/domain";

export async function ReportDetail({
  record,
  report,
}: {
  record: VerdictRecord;
  report: Report;
}) {
  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-8 px-4 py-8 sm:px-6">
      <VerdictHero record={record} />
      <SignalsRow signals={record.signals} />
      <FindingsSection findings={report.findings ?? []} />
      <AiReviewSection
        aiReview={report.aiReview}
        aiError={report.aiError}
        aiFailed={record.aiFailed}
        finalVerdict={record.verdict}
      />
      <div className="grid gap-6 lg:grid-cols-2">
        <PackageInfoCard metadata={report.metadata} />
        <div className="flex flex-col gap-6">
          <IntelSection intel={report.intel} />
          <ScanMetaCard record={record} codeScan={report.codeScan} />
        </div>
      </div>
    </div>
  );
}

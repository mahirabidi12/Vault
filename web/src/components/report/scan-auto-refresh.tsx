"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import { LIVE_SCAN_TOTAL_MS } from "@/lib/api";
import type { ScanStatus } from "@/lib/types/domain";

/**
 * Live-scan pages are server-rendered from a single in-memory simulator
 * (see lib/api.ts). Rather than duplicating that simulation client-side,
 * this component just schedules one `router.refresh()` timed to land after
 * the simulated pipeline finishes, so the server re-renders with the
 * now-COMPLETE (or FAILED/SKIPPED) record. Renders nothing.
 */
export function ScanAutoRefresh({
  status,
  requestedAt,
}: {
  status: ScanStatus;
  requestedAt: string;
}) {
  const router = useRouter();

  React.useEffect(() => {
    if (status !== "PENDING" && status !== "SCANNING") return;
    const startedAt = new Date(requestedAt).getTime();
    const elapsed = Date.now() - startedAt;
    const remaining = Math.max(350, LIVE_SCAN_TOTAL_MS - elapsed + 150);
    const id = setTimeout(() => router.refresh(), remaining);
    return () => clearTimeout(id);
  }, [status, requestedAt, router]);

  return null;
}

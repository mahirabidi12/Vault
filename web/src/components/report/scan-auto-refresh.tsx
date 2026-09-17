"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import type { ScanStatus } from "@/lib/types/domain";

const POLL_INTERVAL_MS = 2000;

/**
 * Live-scan pages are server-rendered. A real scan's duration varies (a quick
 * rules-only check vs. a slower AI deep-dive), so this keeps calling
 * `router.refresh()` on a fixed interval for as long as the scan is still
 * running, instead of guessing a single fixed delay. The server re-fetches
 * the record each time; once it's COMPLETE (or FAILED/SKIPPED), the parent
 * page stops rendering this component, which unmounts it and clears the
 * interval. Renders nothing.
 */
export function ScanAutoRefresh({ status }: { status: ScanStatus }) {
  const router = useRouter();

  React.useEffect(() => {
    if (status !== "PENDING" && status !== "SCANNING") return;
    const id = setInterval(() => router.refresh(), POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [status, router]);

  return null;
}

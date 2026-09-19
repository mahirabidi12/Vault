"use client";

import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import {
  getPackage,
  getReport,
  getStats,
  search,
} from "@/lib/api";
import type { Report, ScanStatus, VerdictRecord } from "@/lib/types/domain";

const LIVE_STATUSES: ScanStatus[] = ["PENDING", "SCANNING"];

export function usePackage(name: string, version?: string): UseQueryResult<VerdictRecord> {
  return useQuery({
    queryKey: ["package", name, version ?? null],
    queryFn: () => getPackage(name, version),
    refetchInterval: (query) => (query.state.data && LIVE_STATUSES.includes(query.state.data.status) ? 500 : false),
  });
}

export function useReport(
  name: string,
  version: string | undefined,
  enabled: boolean
): UseQueryResult<Report | null> {
  return useQuery({
    queryKey: ["report", name, version ?? null],
    queryFn: () => getReport(name, version as string),
    enabled: enabled && !!version,
  });
}

export function useStats() {
  return useQuery({ queryKey: ["stats"], queryFn: () => getStats() });
}

export function useSearch(query: string) {
  return useQuery({
    queryKey: ["search", query],
    queryFn: () => search(query),
    enabled: query.trim().length > 0,
  });
}

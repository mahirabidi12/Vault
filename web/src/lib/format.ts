export function formatBytes(bytes?: number | null): string {
  if (bytes === null || bytes === undefined) return "—";
  if (bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  const value = bytes / Math.pow(1024, i);
  return `${value >= 100 || i === 0 ? Math.round(value) : value.toFixed(1)} ${units[i]}`;
}

export function formatRelativeTime(iso?: string | null): string {
  if (!iso) return "—";
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return "—";
  const diffMs = Date.now() - then;
  const abs = Math.abs(diffMs);
  const sec = Math.round(abs / 1000);
  const suffix = diffMs >= 0 ? "ago" : "from now";

  const units: [number, string][] = [
    [60, "second"],
    [60, "minute"],
    [24, "hour"],
    [30, "day"],
    [12, "month"],
    [Number.POSITIVE_INFINITY, "year"],
  ];
  let value = sec;
  let unitLabel = "second";
  for (const [limit, label] of units) {
    if (value < limit) {
      unitLabel = label;
      break;
    }
    value = Math.floor(value / limit);
    unitLabel = label;
  }
  if (sec < 5) return "just now";
  return `${value} ${unitLabel}${value !== 1 ? "s" : ""} ${suffix}`;
}

export function formatDateTime(iso?: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function truncateMiddle(value: string, headLen = 8, tailLen = 6): string {
  if (value.length <= headLen + tailLen + 3) return value;
  return `${value.slice(0, headLen)}…${value.slice(-tailLen)}`;
}

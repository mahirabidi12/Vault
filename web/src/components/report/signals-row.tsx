import { AlertTriangle } from "lucide-react";

export function SignalsRow({ signals }: { signals?: string[] }) {
  if (!signals || signals.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-2">
      {signals.map((s) => (
        <span
          key={s}
          className="inline-flex items-center gap-1.5 rounded-full border border-suspicious/25 bg-suspicious-bg/70 px-3 py-1 text-xs font-medium text-suspicious"
        >
          <AlertTriangle className="size-3" />
          {s}
        </span>
      ))}
    </div>
  );
}

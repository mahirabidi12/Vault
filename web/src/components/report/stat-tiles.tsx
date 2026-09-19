import { CountUp } from "@/components/count-up";
import { FileCode2, Flame, Terminal, HardDrive } from "lucide-react";
import { cn } from "@/lib/utils";

export type Stat = { label: string; value: number; suffix?: string; icon: "files" | "findings" | "install" | "size"; tone?: "warn" | "bad" };

const ICONS = { files: FileCode2, findings: Flame, install: Terminal, size: HardDrive };

export function StatTiles({ stats }: { stats: Stat[] }) {
  return (
    <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
      {stats.map((s, i) => {
        const Icon = ICONS[s.icon];
        return (
          <div
            key={s.label}
            style={{ animationDelay: `${i * 90}ms` }}
            className="rise-in group relative overflow-hidden rounded-2xl border border-white/10 bg-white/[0.03] p-4 transition-all duration-300 hover:-translate-y-0.5 hover:border-white/25 hover:bg-white/[0.06]"
          >
            <Icon
              className={cn(
                "size-4",
                s.tone === "bad" ? "text-malicious" : s.tone === "warn" ? "text-suspicious" : "text-muted-foreground"
              )}
            />
            <p className="mt-3 font-display text-3xl font-semibold tracking-tight">
              <CountUp value={s.value} />
              {s.suffix && <span className="ml-1 text-base font-normal text-muted-foreground">{s.suffix}</span>}
            </p>
            <p className="mt-0.5 text-xs text-muted-foreground">{s.label}</p>
            <span aria-hidden className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-transparent via-white/30 to-transparent opacity-0 transition-opacity group-hover:opacity-100" />
          </div>
        );
      })}
    </div>
  );
}

import { Check, Minus, ShieldCheck } from "lucide-react";
import { cn } from "@/lib/utils";

type Cell = { text: string; good?: boolean };

const COLUMNS = ["Installing blind", "Reading the code yourself"] as const;

const ROWS: { label: string; others: readonly [Cell, Cell]; pkgguard: Cell }[] = [
  {
    label: "Time per package",
    others: [{ text: "Zero — that's the problem" }, { text: "10–30 minutes, if you're thorough" }],
    pkgguard: { text: "2–7 seconds", good: true },
  },
  {
    label: "Catches known malware",
    others: [{ text: "No" }, { text: "Only if you happen to recognize it" }],
    pkgguard: { text: "Yes — OSV.dev + SafeDep intel", good: true },
  },
  {
    label: "Catches novel supply-chain attacks",
    others: [{ text: "No" }, { text: "Maybe, if you're an expert" }],
    pkgguard: { text: "Static rules + AI code review", good: true },
  },
  {
    label: "Explains itself",
    others: [{ text: "N/A" }, { text: "Only to yourself" }],
    pkgguard: { text: "File, line, rule and reasoning", good: true },
  },
  {
    label: "Works for AI coding agents",
    others: [{ text: "They won't check either" }, { text: "They can't audit for you" }],
    pkgguard: { text: "MCP tool — checked before install", good: true },
  },
  {
    label: "Result is remembered",
    others: [{ text: "Never" }, { text: "Only in your head" }],
    pkgguard: { text: "Scanned once, instant for everyone after", good: true },
  },
];

function Mark({ good }: { good: boolean | undefined }) {
  return good ? (
    <Check aria-label="yes" className="mt-0.5 size-3.5 shrink-0 text-safe" />
  ) : (
    <Minus aria-label="no" className="mt-0.5 size-3.5 shrink-0 text-muted-foreground/40" />
  );
}

export function CompareTable() {
  return (
    <section className="mx-auto w-full max-w-5xl px-4 py-20 sm:px-6">
      <div className="rise mb-10 max-w-2xl">
        <p className="kicker text-brand">Why check at all</p>
        <h2 className="mt-3 font-display text-[clamp(1.7rem,3.6vw,2.5rem)] font-semibold tracking-tight">
          Every other option is slower, or blind.
        </h2>
      </div>

      <div className="rise overflow-x-auto rounded-lg border border-border">
        <table className="w-full min-w-[720px] border-collapse text-left text-[14px]">
          <thead>
            <tr>
              <th scope="col" className="w-[22%] border-b border-r border-border px-4 py-3.5 align-bottom">
                <span className="sr-only">Question</span>
              </th>
              {COLUMNS.map((column) => (
                <th
                  key={column}
                  scope="col"
                  className="w-[26%] border-b border-r border-border px-4 py-3.5 align-bottom text-[13px] font-medium text-muted-foreground"
                >
                  {column}
                </th>
              ))}
              <th scope="col" className="border-b border-border bg-brand/10 px-4 py-3.5 align-bottom">
                <span className="flex items-center gap-1.5 font-display text-[15px] font-semibold text-brand">
                  <ShieldCheck className="size-4" />
                  PkgGuard
                </span>
              </th>
            </tr>
          </thead>
          <tbody>
            {ROWS.map((row, index) => {
              const last = index === ROWS.length - 1;
              return (
                <tr key={row.label}>
                  <th
                    scope="row"
                    className={cn("border-r border-border bg-muted/30 px-4 py-3.5 font-normal text-muted-foreground", !last && "border-b")}
                  >
                    {row.label}
                  </th>
                  {row.others.map((cell, i) => (
                    <td key={i} className={cn("border-r border-border px-4 py-3.5 text-foreground/75", !last && "border-b")}>
                      <span className="flex gap-2">
                        <Mark good={cell.good} />
                        {cell.text}
                      </span>
                    </td>
                  ))}
                  <td className={cn("bg-brand/5 px-4 py-3.5 font-medium text-foreground", !last && "border-b border-border")}>
                    <span className="flex gap-2">
                      <Mark good={row.pkgguard.good} />
                      {row.pkgguard.text}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}

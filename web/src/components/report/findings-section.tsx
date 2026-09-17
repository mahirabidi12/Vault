import { FindingCard } from "@/components/report/finding-card";
import { LayerBadge } from "@/components/verdict-ui";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { LAYER_LABEL, SEVERITY_ORDER } from "@/lib/verdict";
import type { Finding, FindingLayer } from "@/lib/types/domain";
import { ShieldCheck, ChevronDown } from "lucide-react";

const LAYER_ORDER: FindingLayer[] = ["intel", "metadata", "static"];

export async function FindingsSection({ findings }: { findings: Finding[] }) {
  if (findings.length === 0) {
    return (
      <section className="flex items-center gap-3 rounded-lg border border-dashed border-border bg-card/40 p-6 text-sm text-muted-foreground">
        <ShieldCheck className="size-5 text-safe" />
        No findings from threat intelligence, package info or code scanning.
      </section>
    );
  }

  const byLayer = new Map<FindingLayer, Finding[]>();
  for (const f of findings) {
    const arr = byLayer.get(f.layer) ?? [];
    arr.push(f);
    byLayer.set(f.layer, arr);
  }

  return (
    <section className="flex flex-col gap-6">
      <h2 className="font-display text-lg font-semibold tracking-tight">Findings</h2>
      {LAYER_ORDER.filter((l) => byLayer.has(l)).map((layer) => {
        const items = [...byLayer.get(layer)!].sort(
          (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
        );
        const primary = items.filter((f) => f.severity !== "LOW");
        const low = items.filter((f) => f.severity === "LOW");

        return (
          <div key={layer} className="flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <LayerBadge layer={layer} />
              <span className="text-xs text-muted-foreground">
                {items.length} finding{items.length !== 1 ? "s" : ""} · {LAYER_LABEL[layer]}
              </span>
            </div>

            <div className="flex flex-col gap-3">
              {primary.map((f, i) => (
                <FindingCard key={i} finding={f} />
              ))}
            </div>

            {low.length > 0 && (
              <Collapsible>
                <CollapsibleTrigger className="group flex w-fit items-center gap-1.5 rounded-md px-1 text-xs font-medium text-muted-foreground hover:text-foreground">
                  <ChevronDown className="size-3.5 transition-transform group-data-[panel-open]:rotate-180" />
                  {primary.length > 0 ? "Also show" : "Show"} {low.length} low-severity finding
                  {low.length !== 1 ? "s" : ""}
                </CollapsibleTrigger>
                <CollapsibleContent className="mt-3 flex flex-col gap-3">
                  {low.map((f, i) => (
                    <FindingCard key={i} finding={f} />
                  ))}
                </CollapsibleContent>
              </Collapsible>
            )}
          </div>
        );
      })}
    </section>
  );
}

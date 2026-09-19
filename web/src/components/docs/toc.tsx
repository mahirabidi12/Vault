"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

export type TocItem = { id: string; label: string };

/** "On this page" list that follows your scroll and lights up the section you are reading. */
export function Toc({ items }: { items: TocItem[] }) {
  const [active, setActive] = React.useState(items[0]?.id);

  React.useEffect(() => {
    const els = items.map((i) => document.getElementById(i.id)).filter((e): e is HTMLElement => !!e);
    const io = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
        else if (window.scrollY < 400) setActive(items[0]?.id);
      },
      { rootMargin: "-15% 0px -70% 0px" }
    );
    els.forEach((el) => io.observe(el));
    return () => io.disconnect();
  }, [items]);

  const go = (id: string) => (e: React.MouseEvent) => {
    e.preventDefault();
    document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  return (
    <nav aria-label="On this page" className="flex flex-col gap-1">
      <p className="mb-2 font-mono text-[11px] uppercase tracking-wider text-muted-foreground/70">On this page</p>
      {items.map((i) => (
        <a
          key={i.id}
          href={`#${i.id}`}
          onClick={go(i.id)}
          aria-current={active === i.id ? "true" : undefined}
          className={cn(
            "relative rounded-lg px-3 py-2 text-sm transition-colors",
            active === i.id ? "bg-white/[0.07] font-medium text-foreground" : "text-muted-foreground hover:bg-white/[0.04] hover:text-foreground"
          )}
        >
          {active === i.id && <span aria-hidden className="absolute inset-y-2 left-0 w-0.5 rounded-full bg-brand shadow-[0_0_10px_var(--brand)]" />}
          {i.label}
        </a>
      ))}
    </nav>
  );
}

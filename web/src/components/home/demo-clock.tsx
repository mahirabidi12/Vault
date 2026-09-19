"use client";

import * as React from "react";

type Clock = { scenario: number; step: number; started: boolean };

const ClockContext = React.createContext<Clock>({ scenario: 0, step: Number.MAX_SAFE_INTEGER, started: true });

export const useDemoClock = () => React.useContext(ClockContext);

const TICK_MS = 380;
const HOLD_STEPS = 8;

/**
 * One shared clock for every terminal inside it, so they type in lock-step.
 * It only starts once the section is scrolled into view, and pauses while it is off screen.
 * `lengths[i]` is the longest script for scenario i across all terminals.
 */
export function DemoClockProvider({ lengths, children, className }: { lengths: number[]; children: React.ReactNode; className?: string }) {
  const ref = React.useRef<HTMLDivElement>(null);
  const [clock, setClock] = React.useState<Clock>({ scenario: 0, step: 0, started: false });
  const [visible, setVisible] = React.useState(false);
  const [reduce, setReduce] = React.useState(false);

  React.useEffect(() => {
    const el = ref.current;
    if (!el) return;
    const io = new IntersectionObserver(
      ([e]) => {
        setReduce(window.matchMedia("(prefers-reduced-motion: reduce)").matches);
        setVisible(e.isIntersecting && e.intersectionRatio > 0.3);
      },
      { threshold: [0, 0.3, 0.6] }
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  React.useEffect(() => {
    if (!visible || reduce) return;
    const id = setInterval(() => {
      setClock((c) => {
        if (!c.started) return { scenario: 0, step: 1, started: true };
        const next = c.step + 1;
        if (next > lengths[c.scenario] + HOLD_STEPS) return { scenario: (c.scenario + 1) % lengths.length, step: 0, started: true };
        return { ...c, step: next };
      });
    }, TICK_MS);
    return () => clearInterval(id);
  }, [visible, reduce, lengths]);

  // Before it starts (and with reduced motion) show the first script in full instead of an empty window.
  const value: Clock = reduce ? { scenario: 0, step: Number.MAX_SAFE_INTEGER, started: true } : clock;

  return (
    <div ref={ref} className={className}>
      <ClockContext.Provider value={value}>{children}</ClockContext.Provider>
    </div>
  );
}

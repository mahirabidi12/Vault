"use client";

import * as React from "react";

/** Counts from 0 to `value` the first time it scrolls into view. */
export function CountUp({ value, duration = 1200, className }: { value: number; duration?: number; className?: string }) {
  const ref = React.useRef<HTMLSpanElement>(null);
  const [shown, setShown] = React.useState(value);

  React.useEffect(() => {
    const el = ref.current;
    if (!el || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    let raf = 0;
    let started = false;
    const run = () => {
      const t0 = performance.now();
      const tick = (now: number) => {
        const p = Math.min(1, (now - t0) / duration);
        setShown(Math.round(value * (1 - Math.pow(1 - p, 3))));
        if (p < 1) raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
    };
    const io = new IntersectionObserver(([e]) => {
      if (e.isIntersecting && !started) {
        started = true;
        setShown(0);
        run();
        io.disconnect();
      }
    });
    io.observe(el);
    return () => {
      cancelAnimationFrame(raf);
      io.disconnect();
    };
  }, [value, duration]);

  return (
    <span ref={ref} className={className}>
      {shown.toLocaleString()}
    </span>
  );
}

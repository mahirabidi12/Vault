"use client";

import * as React from "react";

type Blob = { color: string; r: number; fx: number; fy: number; px: number; py: number; ax: number; ay: number; a: number };

const BLOBS: Blob[] = [
  { color: "70,100,255", r: 0.5, fx: 0.11, fy: 0.13, px: 0, py: 1, ax: 0.32, ay: 0.16, a: 0.34 },
  { color: "150,80,255", r: 0.44, fx: 0.09, fy: 0.15, px: 2, py: 0.4, ax: 0.36, ay: 0.2, a: 0.3 },
  { color: "40,190,255", r: 0.4, fx: 0.14, fy: 0.1, px: 4, py: 2.2, ax: 0.3, ay: 0.14, a: 0.26 },
  { color: "255,90,170", r: 0.3, fx: 0.08, fy: 0.12, px: 1, py: 3.1, ax: 0.38, ay: 0.18, a: 0.16 },
];

/** Hero background: slow, soft aurora light with a few flowing ribbons. Calm behind text. */
export function AuroraField({ className }: { className?: string }) {
  const ref = React.useRef<HTMLCanvasElement>(null);

  React.useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let w = 0;
    let h = 0;
    let raf = 0;
    let last = 0;
    let clock = 3;
    let visible = true;

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 1.5);
      w = rect.width;
      h = rect.height;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const draw = () => {
      ctx.globalCompositeOperation = "source-over";
      ctx.clearRect(0, 0, w, h);
      ctx.globalCompositeOperation = "lighter";
      const base = Math.max(w, h);

      for (const b of BLOBS) {
        const x = w * (0.5 + b.ax * Math.sin(clock * b.fx * 2 + b.px));
        const y = h * (0.55 + b.ay * Math.sin(clock * b.fy * 2 + b.py));
        const r = base * b.r * (1 + 0.08 * Math.sin(clock * 0.4 + b.px));
        const g = ctx.createRadialGradient(x, y, 0, x, y, r);
        g.addColorStop(0, `rgba(${b.color},${b.a})`);
        g.addColorStop(0.55, `rgba(${b.color},${b.a * 0.25})`);
        g.addColorStop(1, `rgba(${b.color},0)`);
        ctx.fillStyle = g;
        ctx.fillRect(0, 0, w, h);
      }

      // flowing ribbons
      ctx.lineWidth = 1;
      for (let i = 0; i < 7; i++) {
        const k = i / 6;
        ctx.beginPath();
        for (let x = 0; x <= w; x += 12) {
          const nx = x / w;
          const y =
            h * (0.6 + k * 0.28) +
            Math.sin(nx * 5 + clock * 0.35 + i * 0.7) * h * 0.035 * (1 + k) +
            Math.sin(nx * 11 - clock * 0.22 + i) * h * 0.012;
          if (x === 0) ctx.moveTo(x, y);
          else ctx.lineTo(x, y);
        }
        const g = ctx.createLinearGradient(0, 0, w, 0);
        g.addColorStop(0, "rgba(150,175,255,0)");
        g.addColorStop(0.5, `rgba(190,205,255,${0.1 + 0.16 * k})`);
        g.addColorStop(1, "rgba(150,175,255,0)");
        ctx.strokeStyle = g;
        ctx.stroke();
      }
    };

    const step = (now: number) => {
      raf = requestAnimationFrame(step);
      if (!visible) {
        last = now;
        return;
      }
      clock += Math.min(0.05, (now - last) / 1000 || 0);
      last = now;
      draw();
    };

    resize();
    if (reduce) draw();
    else raf = requestAnimationFrame(step);

    const io = new IntersectionObserver(([e]) => (visible = e.isIntersecting));
    io.observe(canvas);
    const ro = new ResizeObserver(() => {
      resize();
      if (reduce) draw();
    });
    ro.observe(canvas);
    return () => {
      cancelAnimationFrame(raf);
      io.disconnect();
      ro.disconnect();
    };
  }, []);

  return <canvas ref={ref} aria-hidden className={className} />;
}

"use client";

import * as React from "react";

type Node = { x: number; y: number; vx: number; vy: number };
type Pulse = { a: number; b: number; p: number; speed: number };
type Threat = { n: number; born: number };

const LINK = 150;

export function NetworkField({ className }: { className?: string }) {
  const ref = React.useRef<HTMLCanvasElement>(null);

  React.useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    let w = 0, h = 0, raf = 0, last = 0, nextThreat = 1.5;
    let nodes: Node[] = [];
    const pulses: Pulse[] = [];
    const threats: Threat[] = [];

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = rect.width; h = rect.height;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      const count = Math.min(110, Math.round((w * h) / 12000));
      nodes = Array.from({ length: count }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.25,
        vy: (Math.random() - 0.5) * 0.25,
      }));
    };

    // keep the centre (headline) calm so text stays readable
    const dim = (x: number, y: number) =>
      1 - 0.88 * Math.exp(-(((x / w - 0.5) / 0.3) ** 2 + ((y / h - 0.45) / 0.3) ** 2));

    const frame = (now: number) => {
      raf = requestAnimationFrame(frame);
      if (now - last < 33) return;
      last = now;
      const t = now / 1000;
      ctx.clearRect(0, 0, w, h);

      for (const n of nodes) {
        if (!reduce) { n.x += n.vx; n.y += n.vy; }
        if (n.x < 0 || n.x > w) n.vx *= -1;
        if (n.y < 0 || n.y > h) n.vy *= -1;
      }

      const flagged = new Set(threats.map((th) => th.n));
      const edges: [number, number][] = [];
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const a = nodes[i], b = nodes[j];
          const d = Math.hypot(a.x - b.x, a.y - b.y);
          if (d < LINK) {
            edges.push([i, j]);
            const bad = flagged.has(i) || flagged.has(j);
            const al = (1 - d / LINK) * 0.35 * dim((a.x + b.x) / 2, (a.y + b.y) / 2);
            ctx.strokeStyle = bad ? `rgba(255,90,80,${al * 2})` : `rgba(255,255,255,${al})`;
            ctx.lineWidth = 1;
            ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke();
          }
        }
      }

      for (const n of nodes) {
        ctx.fillStyle = `rgba(255,255,255,${0.7 * dim(n.x, n.y)})`;
        ctx.beginPath(); ctx.arc(n.x, n.y, 1.6, 0, Math.PI * 2); ctx.fill();
      }

      if (!reduce) {
        if (Math.random() < 0.12 && pulses.length < 26 && edges.length) {
          const [a, b] = edges[Math.floor(Math.random() * edges.length)];
          pulses.push(Math.random() < 0.5 ? { a, b, p: 0, speed: 0.012 + Math.random() * 0.012 } : { a: b, b: a, p: 0, speed: 0.012 + Math.random() * 0.012 });
        }
        for (let i = pulses.length - 1; i >= 0; i--) {
          const pu = pulses[i];
          pu.p += pu.speed;
          if (pu.p >= 1) { pulses.splice(i, 1); continue; }
          const a = nodes[pu.a], b = nodes[pu.b];
          if (Math.hypot(a.x - b.x, a.y - b.y) > LINK) { pulses.splice(i, 1); continue; }
          const x = a.x + (b.x - a.x) * pu.p, y = a.y + (b.y - a.y) * pu.p;
          const al = dim(x, y);
          const g = ctx.createRadialGradient(x, y, 0, x, y, 9);
          g.addColorStop(0, `rgba(255,255,255,${0.9 * al})`);
          g.addColorStop(1, "rgba(255,255,255,0)");
          ctx.fillStyle = g;
          ctx.beginPath(); ctx.arc(x, y, 9, 0, Math.PI * 2); ctx.fill();
        }

        if (t > nextThreat && threats.length < 2) {
          const pool = nodes.map((n, i) => ({ n, i })).filter(({ n }) => dim(n.x, n.y) > 0.6 && n.y > h * 0.25);
          if (pool.length) threats.push({ n: pool[Math.floor(Math.random() * pool.length)].i, born: t });
          nextThreat = t + 2 + Math.random() * 2.5;
        }
      }
      for (let i = threats.length - 1; i >= 0; i--) {
        const th = threats[i];
        const age = t - th.born;
        if (age > 3) { threats.splice(i, 1); continue; }
        const n = nodes[th.n];
        const fade = Math.min(1, (3 - age) / 0.8);
        const r = 5 + ((age * 22) % 26);
        ctx.strokeStyle = `rgba(255,90,80,${(1 - (r - 5) / 26) * fade})`;
        ctx.lineWidth = 1.5;
        ctx.beginPath(); ctx.arc(n.x, n.y, r, 0, Math.PI * 2); ctx.stroke();
        ctx.fillStyle = `rgba(255,90,80,${fade})`;
        ctx.beginPath(); ctx.arc(n.x, n.y, 3.5, 0, Math.PI * 2); ctx.fill();
        ctx.font = "10px ui-monospace, monospace";
        ctx.fillText("MALICIOUS", n.x + 10, n.y - 8);
      }
    };

    resize();
    if (reduce) frame(1000);
    else raf = requestAnimationFrame(frame);
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    return () => { cancelAnimationFrame(raf); ro.disconnect(); };
  }, []);

  return <canvas ref={ref} className={className} aria-hidden="true" />;
}

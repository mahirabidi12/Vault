"use client";

import * as React from "react";

const SPEED = 0.85; // wheel distance multiplier: below 1 means slower than the browser default
const MAX_STEP = 130; // most a single wheel event can move the page, in px
const EASE = 0.14; // how quickly the page catches up with where the wheel asked it to go

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));

function scrollsInside(start: EventTarget | null, dy: number): boolean {
  let el = start instanceof Element ? start : null;
  while (el && el !== document.body && el !== document.documentElement) {
    const style = getComputedStyle(el);
    const scrollable = /(auto|scroll)/.test(style.overflowY) && el.scrollHeight > el.clientHeight + 1;
    if (scrollable) {
      const atTop = el.scrollTop <= 0;
      const atBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 1;
      if ((dy < 0 && !atTop) || (dy > 0 && !atBottom)) return true;
    }
    el = el.parentElement;
  }
  return false;
}

/** Slows and smooths mouse-wheel and trackpad scrolling so the page glides at a gentle, capped speed. */
export function SmoothScroll() {
  React.useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    if (window.matchMedia("(pointer: coarse)").matches) return;

    let target = window.scrollY;
    let current = target;
    let lastSet = target;
    let raf = 0;
    let animating = false;
    const maxScroll = () => Math.max(0, document.documentElement.scrollHeight - window.innerHeight);

    const stop = () => {
      cancelAnimationFrame(raf);
      animating = false;
    };

    const tick = () => {
      // Something else moved the page (a link, a route change): stop steering.
      if (Math.abs(window.scrollY - lastSet) > 3) {
        stop();
        target = current = lastSet = window.scrollY;
        return;
      }
      current += (target - current) * EASE;
      if (Math.abs(target - current) < 0.4) {
        current = target;
        animating = false;
      } else {
        raf = requestAnimationFrame(tick);
      }
      lastSet = current;
      window.scrollTo({ top: current, behavior: "instant" });
    };

    const onWheel = (e: WheelEvent) => {
      if (e.ctrlKey || e.defaultPrevented) return;
      if (Math.abs(e.deltaX) > Math.abs(e.deltaY)) return;
      if (scrollsInside(e.target, e.deltaY)) return;
      e.preventDefault();
      const unit = e.deltaMode === 1 ? 16 : e.deltaMode === 2 ? window.innerHeight : 1;
      target = clamp(target + clamp(e.deltaY * unit * SPEED, -MAX_STEP, MAX_STEP), 0, maxScroll());
      if (!animating) {
        current = lastSet = window.scrollY;
        animating = true;
        raf = requestAnimationFrame(tick);
      }
    };

    const onScroll = () => {
      if (!animating) target = current = lastSet = window.scrollY;
    };

    window.addEventListener("wheel", onWheel, { passive: false });
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => {
      stop();
      window.removeEventListener("wheel", onWheel);
      window.removeEventListener("scroll", onScroll);
    };
  }, []);

  return null;
}

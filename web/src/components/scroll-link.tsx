"use client";

import * as React from "react";
import { usePathname } from "next/navigation";

/**
 * A link to a section of the home page. On the home page it glides to the section without touching the URL,
 * and works every time (a plain #hash link does nothing when the hash is already in the address bar).
 * From any other page it is an ordinary link to `/#section`.
 */
export function ScrollLink({ to, onClick, children, ...props }: { to: string } & Omit<React.ComponentProps<"a">, "href">) {
  const pathname = usePathname();
  return (
    <a
      {...props}
      href={`/#${to}`}
      onClick={(e) => {
        onClick?.(e);
        if (e.defaultPrevented || pathname !== "/") return;
        const el = document.getElementById(to);
        if (!el) return;
        e.preventDefault();
        el.scrollIntoView({ behavior: "smooth", block: "start" });
      }}
    >
      {children}
    </a>
  );
}

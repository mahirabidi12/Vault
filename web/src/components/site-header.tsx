"use client";

import * as React from "react";
import Link from "next/link";
import { Logo } from "@/components/logo";
import { SearchBar } from "@/components/search-bar";
import { Button } from "@/components/ui/button";
import { GithubIcon } from "@/components/icons/github-icon";
import { cn } from "@/lib/utils";

const NAV = [
  { href: "/scan", label: "Scan a project" },
  { href: "/feed", label: "Threat feed" },
  { href: "/docs", label: "Docs" },
];

export function SiteHeader() {
  const [scrolled, setScrolled] = React.useState(false);
  React.useEffect(() => {
    const on = () => setScrolled(window.scrollY > 24);
    on();
    window.addEventListener("scroll", on, { passive: true });
    return () => window.removeEventListener("scroll", on);
  }, []);

  return (
    <header className="pointer-events-none sticky top-0 z-40 px-3 pt-3">
      <div
        className={cn(
          "pointer-events-auto mx-auto flex h-12 max-w-5xl items-center gap-3 rounded-full border px-3 pl-4 transition-all duration-300",
          scrolled
            ? "border-white/10 bg-black/70 shadow-[0_8px_30px_rgba(0,0,0,0.6)] backdrop-blur-md"
            : "border-transparent bg-transparent"
        )}
      >
        <Link href="/" className="flex shrink-0 items-center gap-2 text-[16px] font-semibold tracking-tight">
          <Logo className="size-5" />
          pkgguard
        </Link>

        <nav className="ml-4 hidden items-center gap-0.5 md:flex">
          {NAV.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="rounded-full px-3 py-1.5 text-[13px] text-muted-foreground transition-colors hover:bg-white/8 hover:text-foreground"
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-1.5">
          <SearchBar className="hidden w-52 lg:block" />
          <Button
            variant="ghost"
            size="icon"
            className="rounded-full"
            nativeButton={false}
            render={<a href="https://github.com" target="_blank" rel="noreferrer" aria-label="PkgGuard on GitHub" />}
          >
            <GithubIcon className="size-4" />
          </Button>
          <Button size="sm" className="h-8 rounded-full px-4 text-[13px] font-semibold" render={<Link href="/scan" />} nativeButton={false}>
            Scan
          </Button>
        </div>
      </div>
    </header>
  );
}

"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ArrowRight } from "lucide-react";
import { Logo } from "@/components/logo";
import { ScrollLink } from "@/components/scroll-link";
import { cn } from "@/lib/utils";

const COLUMNS = [
  {
    title: "Product",
    links: [
      { href: "/packages", label: "Scan a package" },
      { href: "/docs", label: "Docs" },
    ],
  },
  {
    title: "Get it",
    links: [
      { href: "/docs#cli", label: "CLI for developers" },
      { href: "/docs#mcp", label: "Agent tool (MCP)" },
      { href: "/docs#api", label: "API" },
      { href: "https://github.com/mahirabidi12/Vault", label: "GitHub" },
    ],
  },
];

export function SiteFooter() {
  const home = usePathname() === "/";
  return (
    <footer data-snap={home ? "" : undefined} className={cn("relative isolate z-20 overflow-hidden", home ? "-mt-24" : "mt-16")}>
      {/* melts the page into the footer instead of cutting it off */}
      <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 -z-10 h-full bg-gradient-to-b from-transparent via-[#05060a]/70 to-[#05060a]" />
      <div
        aria-hidden
        className="pointer-events-none absolute inset-x-0 bottom-0 -z-10 h-2/3 bg-[radial-gradient(ellipse_60%_100%_at_50%_100%,rgba(90,115,255,0.16),transparent_70%)]"
      />

      <div className={cn("mx-auto max-w-6xl px-4 pb-10 sm:px-6", home ? "pt-8" : "pt-4")}>
        {home && (
        <div className="mx-auto max-w-4xl pb-24 pt-12 text-center sm:pb-28">
          <h2 className="text-balance text-[clamp(2.1rem,4.6vw,3.4rem)] font-semibold leading-[1.05] tracking-[-0.04em]">
            Know before you <span className="text-fade">npm install.</span>
          </h2>
          <p className="mt-4 text-base text-muted-foreground">
            Check any package in seconds, from your terminal, your agent, or the browser.
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-3">
            <ScrollLink
              to="get-started"
              className="inline-flex h-12 items-center gap-2 rounded-lg bg-foreground px-6 text-[15px] font-semibold text-background transition-opacity hover:opacity-90"
            >
              Get the CLI <ArrowRight className="size-4" />
            </ScrollLink>
            <Link
              href="/docs"
              className="inline-flex h-12 items-center rounded-lg border border-border bg-black/40 px-6 text-[15px] font-medium transition-colors hover:bg-white/5"
            >
              Read the docs
            </Link>
          </div>
        </div>
        )}

        <div className="grid gap-10 border-t border-white/[0.07] pt-10 sm:grid-cols-[1.4fr_1fr_1fr]">
          <div className="flex flex-col gap-3">
            <span className="flex items-center gap-2 font-display text-lg font-semibold">
              <Logo className="size-6" />
              pkgguard
            </span>
            <p className="max-w-sm text-[15px] leading-relaxed text-muted-foreground">
              A security check for npm packages. Static, dynamic and AI checks, before anything is installed.
            </p>
          </div>
          {COLUMNS.map((col) => (
            <nav key={col.title} aria-label={col.title} className="flex flex-col gap-3 text-[15px]">
              <span className="font-mono text-xs uppercase tracking-wider text-muted-foreground/70">{col.title}</span>
              {col.links.map((l) => (
                <Link
                  key={l.label}
                  href={l.href}
                  {...(l.href.startsWith("http") ? { target: "_blank", rel: "noreferrer" } : {})}
                  className="w-fit text-muted-foreground transition-colors hover:text-foreground"
                >
                  {l.label}
                </Link>
              ))}
            </nav>
          ))}
        </div>

        <p className="mt-10 text-center text-[13px] text-muted-foreground/60">
          © {new Date().getFullYear()} PkgGuard. A SAFE verdict means &ldquo;no issues found&rdquo;, not a guarantee.
        </p>
      </div>

      {/* oversized wordmark that fades out at the very bottom */}
      <div
        aria-hidden
        className="pointer-events-none select-none overflow-hidden text-center font-display text-[clamp(4rem,19vw,17rem)] font-bold leading-[0.8] tracking-[-0.06em] text-white/[0.045] [mask-image:linear-gradient(to_bottom,black_30%,transparent_100%)]"
      >
        pkgguard
      </div>
    </footer>
  );
}

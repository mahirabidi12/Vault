import Link from "next/link";
import { Logo } from "@/components/logo";
import { ThemeToggle } from "@/components/theme-toggle";
import { SearchBar } from "@/components/search-bar";
import { Button } from "@/components/ui/button";
import { GithubIcon } from "@/components/icons/github-icon";

const NAV = [
  { href: "/scan", label: "Scan a project" },
  { href: "/feed", label: "Threat feed" },
  { href: "/docs", label: "Docs" },
];

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-border/60 bg-background/75 backdrop-blur-lg">
      <div className="mx-auto flex h-14 max-w-6xl items-center gap-4 px-4 sm:px-6">
        <Link href="/" className="flex shrink-0 items-center gap-2 font-display text-[17px] font-semibold tracking-tight">
          <Logo />
          <span className="flex items-baseline gap-0.5">
            <span className="font-mono text-brand">$</span>
            <span>pkgguard</span>
          </span>
        </Link>

        <nav className="hidden items-center gap-1 md:flex">
          {NAV.map((item) => (
            <Button
              key={item.href}
              variant="ghost"
              size="sm"
              className="rounded-md text-[13px] text-muted-foreground hover:text-foreground"
              render={<Link href={item.href} />}
              nativeButton={false}
            >
              {item.label}
            </Button>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-2">
          <SearchBar className="hidden w-56 lg:block" />
          <Button
            variant="ghost"
            size="icon"
            nativeButton={false}
            render={
              <a
                href="https://github.com"
                target="_blank"
                rel="noreferrer"
                aria-label="PkgGuard on GitHub"
              />
            }
          >
            <GithubIcon className="size-4" />
          </Button>
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}

import Link from "next/link";
import { LayoutGrid } from "lucide-react";
import { Logo } from "@/components/logo";
import { Button } from "@/components/ui/button";
import { GithubIcon } from "@/components/icons/github-icon";

const NAV = [
  { href: "/docs", label: "Docs" },
];

export function SiteHeader() {
  return (
    <header className="pointer-events-none relative z-40 px-3 pt-3">
      <div
        className="pointer-events-auto mx-auto flex h-14 max-w-5xl items-center gap-3 rounded-full border border-white/10 bg-black/40 px-3.5 pl-5 backdrop-blur-md"
      >
        <Link href="/" className="flex shrink-0 items-center gap-2 text-[17px] font-semibold tracking-tight">
          <Logo className="size-[22px]" />
          pkgguard
        </Link>

        <nav className="ml-4 hidden items-center gap-0.5 md:flex">
          {NAV.map((item) => (
            <Link
              key={item.href}
              href={item.href}
              className="rounded-full px-4 py-2 text-[16px] font-medium text-muted-foreground transition-colors hover:bg-white/8 hover:text-foreground"
            >
              {item.label}
            </Link>
          ))}
        </nav>

        <div className="ml-auto flex items-center gap-1.5">
          <Button
            variant="ghost"
            size="icon"
            className="size-10 rounded-full"
            nativeButton={false}
            render={<a href="https://github.com/mahirabidi12/Vault" target="_blank" rel="noreferrer" aria-label="PkgGuard on GitHub" />}
          >
            <GithubIcon className="size-6" />
          </Button>
          <Button size="sm" className="h-9 gap-2 rounded-full px-5 text-[14px] font-semibold" render={<Link href="/packages" />} nativeButton={false}>
            <LayoutGrid className="size-4" />
            Packages
          </Button>
        </div>
      </div>
    </header>
  );
}

import Link from "next/link";
import { Logo } from "@/components/logo";

export function SiteFooter() {
  return (
    <footer className="border-t border-border/70">
      <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-8 text-sm text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div className="flex items-center gap-2">
          <Logo className="size-4" />
          <span>PkgGuard — a security check for npm packages.</span>
        </div>
        <nav className="flex flex-wrap items-center gap-x-5 gap-y-2">
          <Link href="/scan" className="hover:text-foreground">Scan a project</Link>
          <Link href="/feed" className="hover:text-foreground">Threat feed</Link>
          <Link href="/docs" className="hover:text-foreground">Docs</Link>
          <span className="text-muted-foreground/60">Built for the AWS First Commit hackathon</span>
        </nav>
      </div>
    </footer>
  );
}

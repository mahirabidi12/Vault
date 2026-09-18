import Link from "next/link";
import { SearchBar } from "@/components/search-bar";
import { NetworkField } from "@/components/home/network-field";
import { Ticker } from "@/components/home/ticker";
import { Reveal } from "@/components/reveal";
import { GetStarted } from "@/components/home/get-started";
import { RequestFlow } from "@/components/home/request-flow";
import { LiveStats } from "@/components/home/live-stats";
import { RecentThreats } from "@/components/home/recent-threats";
import { ScanJourney } from "@/components/home/scan-journey";
import { CompareTable } from "@/components/home/compare-table";
import { Button } from "@/components/ui/button";
import { ArrowRight, FileUp } from "lucide-react";

export default function HomePage() {
  return (
    <div className="flex flex-col">
      {/* Hero */}
      <section className="relative flex -mt-[60px] min-h-screen flex-col items-center justify-center overflow-hidden">
        <NetworkField className="pointer-events-none absolute inset-0 h-full w-full [mask-image:linear-gradient(to_bottom,black_55%,transparent_100%)]" />
          <div className="relative flex max-w-4xl flex-col items-center gap-7 px-4 py-24 text-center">
            <span className="animate-fade-up kicker inline-flex items-center gap-1.5 rounded-full border border-border bg-black/60 px-3 py-1.5 text-muted-foreground">
              <span className="size-1.5 rounded-full bg-safe" />
              Built for the AWS First Commit hackathon
            </span>
            <h1
              className="animate-fade-up text-balance text-[clamp(2.8rem,8vw,6rem)] font-bold leading-[1.02] tracking-[-0.05em]"
              style={{ animationDelay: "80ms" }}
            >
              Know before you
              <br />
              <span className="text-fade">npm install.</span>
            </h1>
            <p
              className="animate-fade-up max-w-xl text-balance text-base text-foreground/80 sm:text-lg"
              style={{ animationDelay: "150ms" }}
            >
              PkgGuard checks every npm package for malware and shady install scripts, for humans and for the AI agents that install packages on their own.
            </p>
            <div className="animate-fade-up flex flex-wrap justify-center gap-3" style={{ animationDelay: "220ms" }}>
              <Button size="lg" className="h-11 rounded-lg px-6 text-[15px] font-semibold" render={<Link href="/scan" />} nativeButton={false}>
                Scan a project <ArrowRight className="size-4" />
              </Button>
              <Button size="lg" variant="outline" className="h-11 rounded-lg bg-black/60 px-6 text-[15px] font-medium" render={<Link href="#how-it-works" />} nativeButton={false}>
                How it works
              </Button>
            </div>
            <div className="animate-fade-up flex w-full max-w-xl flex-col gap-3" style={{ animationDelay: "300ms" }}>
              <SearchBar variant="hero" />
              <p className="kicker flex flex-wrap justify-center gap-x-5 gap-y-1.5 text-muted-foreground">
                <span>Try:</span>
                <QuickLink name="esbuild" />
                <QuickLink name="safedep-test-pkg" />
                <QuickLink name="lodash" />
              </p>
            </div>
          </div>
          <p className="kicker absolute inset-x-0 bottom-6 text-center text-muted-foreground/70">
            Checked against npm registry · OSV.dev · SafeDep · AI code review
          </p>
      </section>

      <Ticker />

      <GetStarted />

      {/* One shared brain: CLI + MCP flow */}
      <section className="mx-auto w-full max-w-6xl px-4 py-20 sm:px-6 sm:py-28">
        <Reveal className="mx-auto mb-12 max-w-2xl text-center">
          <p className="kicker text-brand">Two ways in, one source of truth</p>
          <h2 className="mt-3 text-[clamp(1.9rem,4.2vw,3rem)] font-semibold leading-[1.05] tracking-[-0.04em]">
            Every install, human or agent, hits the same verdicts.
          </h2>
          <p className="mt-4 text-muted-foreground">
            The CLI and the agent tool both ask one API, backed by one growing database of scanned packages. A package scanned once is instantly known to everyone.
          </p>
        </Reveal>
        <Reveal delay={100}>
          <RequestFlow />
        </Reveal>
      </section>

      {/* Live stats */}
      <section className="mx-auto -mt-2 w-full max-w-5xl px-4 py-10 sm:px-6">
        <Reveal><LiveStats /></Reveal>
      </section>

      {/* Sticky-scroll pipeline story */}
      <div className="dots border-y border-border/60">
        <ScanJourney />
      </div>

      {/* Why check at all */}
      <Reveal><CompareTable /></Reveal>

      {/* Recent threats + scan CTA */}
      <section className="mx-auto w-full max-w-5xl px-4 pb-24 sm:px-6">
        <div className="rise grid gap-6 lg:grid-cols-[1.4fr_1fr]">
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <h2 className="font-display text-lg font-semibold tracking-tight">Recently caught</h2>
              <Button variant="ghost" size="sm" render={<Link href="/feed" />} nativeButton={false}>
                View feed <ArrowRight className="size-3.5" />
              </Button>
            </div>
            <Reveal delay={100}><RecentThreats /></Reveal>
          </div>

          <div className="flex flex-col justify-between gap-4 rounded-lg border border-brand/25 bg-gradient-to-br from-accent/50 to-transparent p-6">
            <div className="flex flex-col gap-2">
              <span className="flex size-9 items-center justify-center rounded-md bg-brand/10 text-brand">
                <FileUp className="size-4.5" />
              </span>
              <h3 className="font-display font-semibold">Scan a whole project</h3>
              <p className="text-sm text-muted-foreground">
                Drop in a <code className="rounded bg-muted px-1 py-0.5 text-xs">package-lock.json</code> and see
                every dependency&apos;s verdict at once. Nothing leaves your browser.
              </p>
            </div>
            <Button render={<Link href="/scan" />} nativeButton={false} className="w-fit">
              Scan a project <ArrowRight className="size-4" />
            </Button>
          </div>
        </div>
      </section>
    </div>
  );
}

function QuickLink({ name }: { name: string }) {
  return (
    <Link href={`/npm/${name}`} className="underline decoration-dotted underline-offset-4 hover:text-foreground">
      {name}
    </Link>
  );
}

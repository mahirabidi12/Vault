import Link from "next/link";
import { SearchBar } from "@/components/search-bar";
import { AuroraField } from "@/components/home/aurora-field";
import { Ticker } from "@/components/home/ticker";
import { Reveal } from "@/components/reveal";
import { GetStarted } from "@/components/home/get-started";
import { RequestFlow } from "@/components/home/request-flow";
import { LiveStats } from "@/components/home/live-stats";
import { RecentThreats } from "@/components/home/recent-threats";
import { ScanJourney } from "@/components/home/scan-journey";
import { Button } from "@/components/ui/button";
import { ArrowRight } from "lucide-react";

export default function HomePage() {
  return (
    <div className="flex flex-col">
      {/* Hero */}
      <section className="relative flex -mt-[60px] min-h-screen flex-col items-center justify-center overflow-hidden">
        <AuroraField className="pointer-events-none absolute inset-0 h-full w-full [mask-image:linear-gradient(to_bottom,black_65%,transparent_100%)]" />
        <div aria-hidden className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_45%_42%_at_50%_46%,rgba(0,0,0,0.55),transparent_100%)]" />
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
              PkgGuard checks every npm package for malware and shady install scripts. Use the CLI in your terminal, or give your AI agent a tool that checks before it installs.
            </p>
            <div className="animate-fade-up flex flex-wrap justify-center gap-3" style={{ animationDelay: "220ms" }}>
              <Button size="lg" className="h-11 rounded-lg px-6 text-[15px] font-semibold" render={<Link href="/scan" />} nativeButton={false}>
                Scan a project <ArrowRight className="size-4" />
              </Button>
              <Button size="lg" variant="outline" className="h-11 rounded-lg bg-black/60 px-6 text-[15px] font-medium" render={<Link href="#how-it-works" />} nativeButton={false}>
                How it works
              </Button>
              <Button size="lg" variant="outline" className="h-11 rounded-lg bg-black/60 px-6 text-[15px] font-medium" render={<Link href="#get-started" />} nativeButton={false}>
                Get the CLI
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
            Every install, from your terminal or your agent, hits the same verdicts.
          </h2>
          <p className="mt-4 text-muted-foreground">
            The CLI and the agent tool both ask one API. It runs static, dynamic and agent checks once, then remembers the verdict, so a package scanned once is instantly known to everyone.
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

      {/* Step-by-step journey; soft fades at both edges so it melts into the page */}
      <div className="relative">
        <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 z-10 h-24 bg-gradient-to-b from-background to-transparent" />
        <div className="dots">
          <ScanJourney />
        </div>
        <div aria-hidden className="pointer-events-none absolute inset-x-0 bottom-0 z-10 h-32 bg-gradient-to-t from-background to-transparent" />
      </div>

      {/* Recent threats */}
      <section className="mx-auto w-full max-w-5xl px-4 pb-24 sm:px-6">
        <div className="flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <h2 className="font-display text-lg font-semibold tracking-tight">Recently caught</h2>
            <Button variant="ghost" size="sm" render={<Link href="/feed" />} nativeButton={false}>
              View feed <ArrowRight className="size-3.5" />
            </Button>
          </div>
          <Reveal delay={100}><RecentThreats /></Reveal>
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

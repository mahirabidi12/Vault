import Link from "next/link";
import { SearchBar } from "@/components/search-bar";
import { AuroraField } from "@/components/home/aurora-field";
import { HeroTitle } from "@/components/home/hero-title";
import { Ticker } from "@/components/home/ticker";
import { Reveal } from "@/components/reveal";
import { GetStarted } from "@/components/home/get-started";
import { RequestFlow } from "@/components/home/request-flow";
import { LiveStats } from "@/components/home/live-stats";
import { ScanJourney } from "@/components/home/scan-journey";
import { Button } from "@/components/ui/button";
import { ArrowRight } from "lucide-react";

export default function HomePage() {
  return (
    <div className="flex flex-col">
      {/* Hero */}
      <section data-snap className="relative flex -mt-[68px] min-h-screen flex-col items-center justify-center overflow-hidden">
        <AuroraField className="pointer-events-none absolute inset-0 h-full w-full [mask-image:linear-gradient(to_bottom,black_65%,transparent_100%)]" />
        <div aria-hidden className="pointer-events-none absolute inset-0 bg-[radial-gradient(ellipse_45%_42%_at_50%_46%,rgba(0,0,0,0.55),transparent_100%)]" />
          <div className="relative flex max-w-4xl flex-col items-center gap-7 px-4 py-24 text-center">
            <HeroTitle />
            <p
              className="animate-fade-up max-w-xl text-balance text-base text-foreground/80 sm:text-lg"
              style={{ animationDelay: "2000ms" }}
            >
              PkgGuard checks every npm package for malware and shady install scripts. Use the CLI in your terminal, or give your AI agent a tool that checks before it installs.
            </p>
            <div className="animate-fade-up flex flex-wrap justify-center gap-3" style={{ animationDelay: "2200ms" }}>
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
            <div className="animate-fade-up flex w-full max-w-xl flex-col gap-3" style={{ animationDelay: "2400ms" }}>
              <SearchBar variant="hero" />
              <p className="kicker flex flex-wrap justify-center gap-x-5 gap-y-1.5 text-muted-foreground">
                <span>Try:</span>
                <QuickLink name="esbuild" />
                <QuickLink name="safedep-test-pkg" />
                <QuickLink name="lodash" />
              </p>
            </div>
          </div>
        <Ticker className="absolute inset-x-0 bottom-0 z-10 bg-gradient-to-t from-black/70 to-transparent" />
      </section>

      {/* Live stats, under the ticker */}
      <section data-snap className="mx-auto flex min-h-[100svh] w-full max-w-6xl flex-col justify-center px-4 py-16 sm:px-6">
        <Reveal><LiveStats /></Reveal>
      </section>

      <GetStarted />

      {/* One shared brain: CLI + MCP flow */}
      <section data-snap className="mx-auto flex min-h-[100svh] w-full max-w-6xl flex-col justify-center px-4 py-16 sm:px-6">
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

      {/* Step-by-step journey; soft fades at both edges so it melts into the page */}
      <div data-snap className="relative">
        <div aria-hidden className="pointer-events-none absolute inset-x-0 top-0 z-10 h-24 bg-gradient-to-b from-background to-transparent" />
        <div className="dots">
          <ScanJourney />
        </div>
        <div aria-hidden className="pointer-events-none absolute inset-x-0 bottom-0 z-10 h-32 bg-gradient-to-t from-background to-transparent" />
      </div>
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

import Link from "next/link";
import { SearchBar } from "@/components/search-bar";
import { HeroSceneLoader } from "@/components/home/hero-scene-loader";
import { LiveStats } from "@/components/home/live-stats";
import { RecentThreats } from "@/components/home/recent-threats";
import { TerminalBlock } from "@/components/terminal-block";
import { Button } from "@/components/ui/button";
import {
  Download,
  Radar,
  Code2,
  Sparkles,
  ArrowRight,
  FileUp,
  Bot,
} from "lucide-react";

const PIPELINE = [
  {
    icon: Download,
    title: "Fetch",
    body: "Download the exact published tarball and verify it against the registry's integrity hash.",
  },
  {
    icon: Radar,
    title: "Threat intel",
    body: "Check OSV.dev and SafeDep for known malware advisories before reading a single line of code.",
  },
  {
    icon: Code2,
    title: "Code + package info",
    body: "Static analysis of install scripts and source, plus red flags like typosquats and new maintainers.",
  },
  {
    icon: Sparkles,
    title: "AI triage",
    body: "When something looks off, an AI agent reads the actual code and explains what it found — and why.",
  },
];

export default function HomePage() {
  return (
    <div className="flex flex-col">
      {/* Hero */}
      <section className="relative overflow-hidden border-b border-border/60">
        <div className="bg-grid pointer-events-none absolute inset-0 [mask-image:radial-gradient(ellipse_60%_60%_at_50%_0%,black,transparent)]" />
        <div className="relative h-[420px] sm:h-[480px]">
          <HeroSceneLoader />
        </div>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center px-4 text-center">
          <div className="pointer-events-auto flex flex-col items-center gap-6">
            <span className="animate-fade-up inline-flex items-center gap-1.5 rounded-full border border-border bg-card/70 px-3 py-1 text-xs font-medium text-muted-foreground backdrop-blur-sm">
              <Sparkles className="size-3.5 text-brand" />
              Built for the AWS First Commit hackathon
            </span>
            <h1
              className="animate-fade-up text-balance text-4xl font-semibold tracking-tight sm:text-6xl"
              style={{ animationDelay: "80ms" }}
            >
              Know before you
              <br className="hidden sm:block" /> <span className="text-brand">npm install</span>.
            </h1>
            <p
              className="animate-fade-up max-w-xl text-balance text-base text-muted-foreground sm:text-lg"
              style={{ animationDelay: "150ms" }}
            >
              PkgGuard checks every npm package for malware, supply-chain attacks and shady install
              scripts — for humans, and for the AI agents that install packages on their own.
            </p>
            <div
              className="animate-fade-up flex w-full max-w-xl flex-col gap-3 sm:flex-row"
              style={{ animationDelay: "220ms" }}
            >
              <SearchBar variant="hero" autoFocus />
            </div>
            <p className="animate-fade-up text-xs text-muted-foreground" style={{ animationDelay: "260ms" }}>
              Try it: <QuickLink name="esbuild" /> · <QuickLink name="safedep-test-pkg" /> ·{" "}
              <QuickLink name="lodash" />
            </p>
          </div>
        </div>
      </section>

      {/* Live stats */}
      <section className="mx-auto -mt-2 w-full max-w-5xl px-4 py-10 sm:px-6">
        <LiveStats />
      </section>

      {/* Pipeline */}
      <section className="border-y border-border/60 bg-muted/20 py-16">
        <div className="mx-auto max-w-5xl px-4 sm:px-6">
          <div className="mb-10 flex flex-col gap-2 text-center">
            <h2 className="text-2xl font-semibold tracking-tight">How a verdict gets decided</h2>
            <p className="text-sm text-muted-foreground">
              Nothing is ever labeled &quot;safe&quot; on a guess. Every step is recorded as evidence.
            </p>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {PIPELINE.map((step, i) => (
              <div key={step.title} className="relative flex flex-col gap-3 rounded-2xl border border-border bg-card/60 p-5">
                <span className="absolute right-4 top-4 font-mono text-xs text-muted-foreground/50">
                  0{i + 1}
                </span>
                <span className="flex size-9 items-center justify-center rounded-lg bg-brand/10 text-brand">
                  <step.icon className="size-4.5" />
                </span>
                <h3 className="text-sm font-semibold">{step.title}</h3>
                <p className="text-xs leading-relaxed text-muted-foreground">{step.body}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Install snippets */}
      <section className="mx-auto w-full max-w-5xl px-4 py-16 sm:px-6">
        <div className="grid gap-6 lg:grid-cols-2">
          <div className="flex flex-col gap-4 rounded-2xl border border-border bg-card/60 p-6">
            <div className="flex items-center gap-2">
              <span className="flex size-8 items-center justify-center rounded-lg bg-brand/10 text-brand">
                <Download className="size-4" />
              </span>
              <h3 className="font-semibold">CLI</h3>
            </div>
            <p className="text-sm text-muted-foreground">
              Checks your whole dependency tree, then runs the real install only if it&apos;s clean.
            </p>
            <TerminalBlock command="npx pkgguard install express" />
            <Link href="/docs" className="inline-flex w-fit items-center gap-1 text-xs font-medium text-brand hover:underline">
              CLI setup <ArrowRight className="size-3" />
            </Link>
          </div>

          <div className="flex flex-col gap-4 rounded-2xl border border-border bg-card/60 p-6">
            <div className="flex items-center gap-2">
              <span className="flex size-8 items-center justify-center rounded-lg bg-brand/10 text-brand">
                <Bot className="size-4" />
              </span>
              <h3 className="font-semibold">Agent tool (MCP)</h3>
            </div>
            <p className="text-sm text-muted-foreground">
              Give Claude Code, Cursor or any MCP client a <code className="rounded bg-muted px-1 py-0.5 text-xs">check_package</code> tool it must call before installing anything.
            </p>
            <TerminalBlock command="npx pkgguard-mcp@1.0.0" label="mcp" />
            <Link href="/docs" className="inline-flex w-fit items-center gap-1 text-xs font-medium text-brand hover:underline">
              Agent setup <ArrowRight className="size-3" />
            </Link>
          </div>
        </div>
      </section>

      {/* Recent threats + scan CTA */}
      <section className="mx-auto w-full max-w-5xl px-4 pb-20 sm:px-6">
        <div className="grid gap-6 lg:grid-cols-[1.4fr_1fr]">
          <div className="flex flex-col gap-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold tracking-tight">Recently caught</h2>
              <Button variant="ghost" size="sm" render={<Link href="/feed" />}>
                View feed <ArrowRight className="size-3.5" />
              </Button>
            </div>
            <RecentThreats />
          </div>

          <div className="flex flex-col justify-between gap-4 rounded-2xl border border-brand/20 bg-gradient-to-br from-accent/50 to-transparent p-6">
            <div className="flex flex-col gap-2">
              <span className="flex size-9 items-center justify-center rounded-lg bg-brand/10 text-brand">
                <FileUp className="size-4.5" />
              </span>
              <h3 className="font-semibold">Scan a whole project</h3>
              <p className="text-sm text-muted-foreground">
                Drop in a <code className="rounded bg-muted px-1 py-0.5 text-xs">package-lock.json</code> and see
                every dependency&apos;s verdict at once. Nothing leaves your browser.
              </p>
            </div>
            <Button render={<Link href="/scan" />} className="w-fit">
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
    <Link href={`/npm/${name}`} className="font-mono underline decoration-dotted underline-offset-2 hover:text-foreground">
      {name}
    </Link>
  );
}

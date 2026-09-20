import type { Metadata } from "next";
import type { ReactNode } from "react";
import Link from "next/link";
import { ArrowUpRight, Bot, Globe, Lock, ShieldAlert, ShieldCheck, ShieldX, Terminal } from "lucide-react";
import { TerminalBlock } from "@/components/terminal-block";
import { CodeBlock } from "@/components/docs/code-block";
import { McpTabs } from "@/components/docs/mcp-tabs";
import { Toc, type TocItem } from "@/components/docs/toc";
import { Reveal } from "@/components/reveal";
import { cn } from "@/lib/utils";

export const metadata: Metadata = { title: "Docs" };

const API_URL = "https://632dcqt3l3.execute-api.ap-south-1.amazonaws.com";

const TOC: TocItem[] = [
  { id: "verdicts", label: "Reading a verdict" },
  { id: "cli", label: "CLI" },
  { id: "mcp", label: "Agent tool (MCP)" },
  { id: "api", label: "API" },
  { id: "privacy", label: "Privacy" },
];

const QUICKSTART = [
  { id: "cli", icon: Terminal, title: "CLI", who: "For developers", command: "npx pkgguard-cli install express", accent: "96,165,250" },
  { id: "mcp", icon: Bot, title: "Agent tool", who: "For your AI agent", command: "claude mcp add pkgguard -- npx -y pkgguard-mcp@0.1.2", accent: "167,139,250" },
  { id: "api", icon: Globe, title: "API", who: "For your own tools", command: "GET /v1/package?ecosystem=npm&name=express", accent: "52,211,153" },
];

const EXAMPLE_REQUEST = `curl "${API_URL}/v1/package?ecosystem=npm&name=express&version=5.2.1"`;
const EXAMPLE_RESPONSE = `{
  "package": { "ecosystem": "npm", "name": "express", "version": "5.2.1" },
  "status": "COMPLETE",
  "verdict": "SAFE",
  "confidence": "HIGH",
  "decidedBy": "ai",
  "summary": "Express 5.2.1 is the legitimate web framework with no malicious code, install scripts, or suspicious behavior."
}`;

export default function DocsPage() {
  return (
    <div className="mx-auto max-w-6xl px-4 pb-24 pt-10 sm:px-6 sm:pt-16">
      {/* header */}
      <header className="relative isolate overflow-hidden rounded-3xl border border-white/10 bg-white/[0.02] p-6 sm:p-10">
        <div aria-hidden className="pointer-events-none absolute inset-0 -z-10">
          <div className="blob-drift absolute -right-10 -top-24 size-72 rounded-full bg-brand/15 blur-3xl" />
          <div className="bg-grid absolute inset-0 opacity-40 [mask-image:radial-gradient(ellipse_70%_90%_at_80%_20%,black,transparent)]" />
        </div>
        <p className="kicker text-brand">Docs</p>
        <h1 className="mt-3 max-w-3xl text-balance font-display text-[clamp(2rem,5vw,3.6rem)] font-semibold leading-[1.03] tracking-[-0.04em]">
          Check a package <span className="text-fade">before it runs.</span>
        </h1>
        <p className="mt-4 max-w-2xl text-[15px] leading-relaxed text-muted-foreground sm:text-base">
          Use PkgGuard from your terminal, from an AI agent, or over the API. Every route asks the same service, so a package scanned once has the same verdict everywhere.
        </p>

        <div className="mt-8 grid gap-3 md:grid-cols-3">
          {QUICKSTART.map((q) => (
            <a
              key={q.id}
              href={`#${q.id}`}
              className="group relative flex flex-col gap-3 overflow-hidden rounded-2xl border border-white/10 bg-black/40 p-4 transition-all duration-300 hover:-translate-y-1 hover:border-white/25"
            >
              <span aria-hidden className="absolute inset-x-0 top-0 h-px" style={{ background: `linear-gradient(90deg, transparent, rgba(${q.accent},0.9), transparent)` }} />
              <div className="flex items-center gap-3">
                <span className="flex size-9 items-center justify-center rounded-xl border" style={{ borderColor: `rgba(${q.accent},0.4)`, background: `rgba(${q.accent},0.12)`, color: `rgb(${q.accent})` }}>
                  <q.icon className="size-4.5" />
                </span>
                <div>
                  <p className="font-display text-base font-semibold leading-tight">{q.title}</p>
                  <p className="text-xs text-muted-foreground">{q.who}</p>
                </div>
                <ArrowUpRight className="ml-auto size-4 text-muted-foreground transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-foreground" />
              </div>
              <code className="line-clamp-2 break-all rounded-lg border border-white/8 bg-white/[0.03] px-3 py-2 font-mono text-[12px] leading-snug text-zinc-300">{q.command}</code>
            </a>
          ))}
        </div>
      </header>

      <div className="mt-10 grid gap-10 lg:grid-cols-[13rem_minmax(0,1fr)] lg:gap-14">
        <aside className="hidden lg:block">
          <div className="sticky top-8">
            <Toc items={TOC} />
          </div>
        </aside>

        <div className="flex min-w-0 flex-col gap-14">
          {/* verdicts */}
          <Section id="verdicts" icon={ShieldCheck} title="Reading a verdict" lead="Every package ends with one of three verdicts, a confidence level, and the layer that decided it.">
            <div className="grid gap-3 sm:grid-cols-3">
              <Verdict icon={ShieldCheck} tone="safe" name="No issues found" text="Nothing in threat intelligence, package info, code or the sandbox run triggered a warning." />
              <Verdict icon={ShieldAlert} tone="suspicious" name="Suspicious" text="Something is unusual enough to look at before you install. The CLI asks you to confirm." />
              <Verdict icon={ShieldX} tone="malicious" name="Malicious" text="Strong evidence the package is harmful. The CLI blocks it and your agent refuses." />
            </div>
            <ul className="grid gap-2 text-sm sm:grid-cols-2">
              <Note title="Decided by threat intel or the sandbox">Final. A known-malware match, or a fake credential seen leaving the sandbox, cannot be overridden by the AI.</Note>
              <Note title="Decided by the AI review or the rules">A judgment with a confidence level, based on what the code and the sandbox recording show.</Note>
            </ul>
            <p className="text-xs text-muted-foreground">A verdict of &quot;no issues found&quot; is not a guarantee. It means nothing we can detect was wrong.</p>
          </Section>

          {/* cli */}
          <Section id="cli" icon={Terminal} title="CLI" lead="Nothing to set up. Run it in front of any install (Node.js 18 or newer). The first time, npx asks to download it. Answer y.">
            <Step n={1} title="Install a package, checked first">
              <TerminalBlock command="npx pkgguard-cli install express" />
              <p className="text-sm leading-relaxed text-muted-foreground">
                Checks the packages you name, then blocks on anything <b className="font-medium text-malicious">malicious</b>, warns and asks to confirm on anything <b className="font-medium text-suspicious">suspicious</b>, and only then runs the real <Code>npm install</Code>, with the exact versions it checked. You see one line per check (threat intel, package info, static scan, sandbox, AI review), then the verdict.
              </p>
            </Step>
            <Step n={2} title="Check its dependencies too">
              <TerminalBlock command="npx pkgguard-cli install express --deep" />
              <p className="text-sm leading-relaxed text-muted-foreground">
                <Code>--deep</Code> also checks every dependency of what you install. Packages nobody has scanned yet are scanned on the spot, so a big tree can take a few minutes the first time.
              </p>
            </Step>
            <Step n={3} title="Check without installing">
              <TerminalBlock command="npx pkgguard-cli check lodash" />
              <p className="text-sm leading-relaxed text-muted-foreground">
                Checks one package without installing it. Run <Code>check</Code> with no name inside a project to check every package in its lockfile.
              </p>
            </Step>

            <div className="grid gap-4 lg:grid-cols-2">
              <div className="overflow-hidden rounded-2xl border border-white/10">
                <p className="border-b border-white/10 bg-white/[0.03] px-4 py-2.5 text-sm font-semibold">Options</p>
                <dl className="divide-y divide-white/8 text-sm">
                  <Opt flag="--deep" text="Also check every dependency (install only)." />
                  <Opt flag="-y, --yes" text="Skip the confirmation for suspicious packages. Malicious ones are always blocked." />
                  <Opt flag="-q, --quiet" text="Print only the verdict, not the per-check log." />
                  <Opt flag="--json" text="Print machine-readable JSON." />
                </dl>
              </div>
              <div className="overflow-hidden rounded-2xl border border-white/10">
                <p className="border-b border-white/10 bg-white/[0.03] px-4 py-2.5 text-sm font-semibold">Exit codes</p>
                <ul className="divide-y divide-white/8 text-sm">
                  <Exit code="0" tone="safe" text="Fine, nothing to flag." />
                  <Exit code="1" tone="suspicious" text="Needs a look." />
                  <Exit code="2" tone="malicious" text="Blocked. Nothing was installed." />
                  <Exit code="3" tone="muted" text="Could not finish." />
                </ul>
              </div>
            </div>
          </Section>

          {/* mcp */}
          <Section
            id="mcp"
            icon={Bot}
            title="Agent tool (MCP)"
            lead="Give any MCP-compatible agent (Claude Code, Cursor, …) a check_package tool it must call before installing anything. Pin the version: don't let the thing that checks your supply chain be an unchecked supply chain itself."
          >
            <McpTabs />
            <div>
              <p className="mb-3 text-sm font-semibold">What your agent is told</p>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                <Outcome label="ALLOW" tone="safe" text="No issues found. Go ahead." />
                <Outcome label="WARN" tone="suspicious" text="Confirm with you before installing." />
                <Outcome label="BLOCK" tone="malicious" text="Refuse, and tell you why." />
                <Outcome label="WAIT" tone="muted" text="Scan still running. Don't install yet." />
              </div>
            </div>
          </Section>

          {/* api */}
          <Section id="api" icon={Globe} title="API" lead="The CLI, agent tool and website all call the same public API. No key is needed.">
            <TerminalBlock command={API_URL} label="base" wrap className="text-[13px]" />
            <div className="flex flex-col gap-2">
              <Endpoint method="GET" path="/v1/package?ecosystem=npm&name=&version=" desc="Verdict, or 202 + scanId if not scanned yet" />
              <Endpoint method="POST" path="/v1/check" desc='Batch check. Body: {"packages": [{ecosystem,name,version}]}, max 200 per request' />
              <Endpoint method="GET" path="/v1/report?ecosystem=npm&name=&version=" desc="Full report of a finished scan (exact version)" />
              <Endpoint method="GET" path="/v1/scans/{scanId}" desc="Poll a scan in progress" />
              <Endpoint method="GET" path="/v1/package/versions?ecosystem=npm&name=" desc="All scanned versions of a package" />
              <Endpoint method="GET" path="/v1/feed" desc="Recent malicious / suspicious verdicts" />
            </div>
            <div className="grid gap-4">
              <div className="flex min-w-0 flex-col gap-2">
                <p className="text-sm font-semibold">Request</p>
                <CodeBlock code={EXAMPLE_REQUEST} lang="bash" />
              </div>
              <div className="flex min-w-0 flex-col gap-2">
                <p className="text-sm font-semibold">Response</p>
                <CodeBlock code={EXAMPLE_RESPONSE} lang="json" />
              </div>
            </div>
            <p className="text-xs leading-relaxed text-muted-foreground">
              Open for now, with no sign-up. Scanning a package nobody has checked before takes a minute or two, so the first lookup can answer 202 and you poll until it finishes. Personal API keys with quotas are planned.
            </p>
          </Section>

          {/* privacy */}
          <Section id="privacy" icon={Lock} title="Privacy">
            <div className="flex items-start gap-4 rounded-2xl border border-safe/25 bg-safe-bg/50 p-5">
              <span className="flex size-10 shrink-0 items-center justify-center rounded-xl border border-safe/30 bg-safe/10 text-safe">
                <Lock className="size-5" />
              </span>
              <p className="text-[15px] leading-relaxed text-foreground/85">
                The CLI and agent tool send only package names and exact versions to PkgGuard: never your source code, environment variables, or the rest of your <Code>package.json</Code>.
              </p>
            </div>
          </Section>

          <p className="text-sm text-muted-foreground">
            Something missing? <Link href="https://github.com/mahirabidi12/Vault" className="text-foreground underline underline-offset-4">Open an issue on GitHub</Link>.
          </p>
        </div>
      </div>
    </div>
  );
}

function Section({ id, icon: Icon, title, lead, children }: { id: string; icon: typeof Terminal; title: string; lead?: string; children: ReactNode }) {
  return (
    <Reveal>
      <section id={id} className="flex scroll-mt-8 flex-col gap-6">
        <header className="flex flex-col gap-2">
          <h2 className="flex items-center gap-3 font-display text-2xl font-semibold tracking-tight sm:text-3xl">
            <span className="flex size-10 items-center justify-center rounded-xl border border-white/10 bg-white/[0.05]">
              <Icon className="size-5 text-brand" />
            </span>
            {title}
          </h2>
          {lead && <p className="max-w-3xl text-[15px] leading-relaxed text-muted-foreground">{lead}</p>}
        </header>
        {children}
      </section>
    </Reveal>
  );
}

function Step({ n, title, children }: { n: number; title: string; children: ReactNode }) {
  return (
    <div className="flex gap-4">
      <div className="flex flex-col items-center">
        <span className="flex size-8 shrink-0 items-center justify-center rounded-full border border-brand/40 bg-brand/10 font-mono text-sm font-semibold text-brand">{n}</span>
        <span aria-hidden className="mt-2 w-px flex-1 bg-gradient-to-b from-white/15 to-transparent" />
      </div>
      <div className="flex min-w-0 flex-1 flex-col gap-3 pb-4">
        <h3 className="font-display text-lg font-semibold tracking-tight">{title}</h3>
        {children}
      </div>
    </div>
  );
}

function Code({ children }: { children: ReactNode }) {
  return <code className="rounded-md border border-white/10 bg-white/[0.05] px-1.5 py-0.5 font-mono text-[0.85em] text-foreground">{children}</code>;
}

const TONES = {
  safe: "border-safe/30 bg-safe/[0.07] text-safe",
  suspicious: "border-suspicious/30 bg-suspicious/[0.07] text-suspicious",
  malicious: "border-malicious/35 bg-malicious/[0.07] text-malicious",
  muted: "border-white/12 bg-white/[0.04] text-muted-foreground",
} as const;

function Verdict({ icon: Icon, tone, name, text }: { icon: typeof ShieldCheck; tone: "safe" | "suspicious" | "malicious"; name: string; text: string }) {
  return (
    <div className={cn("flex flex-col gap-3 rounded-2xl border p-4", TONES[tone])}>
      <span className="flex items-center gap-2 font-display text-base font-semibold">
        <Icon className="size-5" /> {name}
      </span>
      <p className="text-[13px] leading-relaxed text-foreground/80">{text}</p>
    </div>
  );
}

function Note({ title, children }: { title: string; children: ReactNode }) {
  return (
    <li className="rounded-2xl border border-white/10 bg-white/[0.03] p-4">
      <p className="font-semibold">{title}</p>
      <p className="mt-1 text-[13px] leading-relaxed text-muted-foreground">{children}</p>
    </li>
  );
}

function Opt({ flag, text }: { flag: string; text: string }) {
  return (
    <div className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-baseline sm:gap-4">
      <dt className="w-28 shrink-0 font-mono text-[13px] text-brand">{flag}</dt>
      <dd className="text-muted-foreground">{text}</dd>
    </div>
  );
}

function Exit({ code, tone, text }: { code: string; tone: keyof typeof TONES; text: string }) {
  return (
    <li className="flex items-center gap-3 px-4 py-3">
      <span className={cn("flex size-7 items-center justify-center rounded-lg border font-mono text-sm font-semibold", TONES[tone])}>{code}</span>
      <span className="text-muted-foreground">{text}</span>
    </li>
  );
}

function Outcome({ label, tone, text }: { label: string; tone: keyof typeof TONES; text: string }) {
  return (
    <div className={cn("rounded-2xl border p-3.5", TONES[tone])}>
      <p className="font-mono text-sm font-semibold tracking-wider">{label}</p>
      <p className="mt-1 text-[13px] leading-snug text-foreground/75">{text}</p>
    </div>
  );
}

function Endpoint({ method, path, desc }: { method: string; path: string; desc: string }) {
  return (
    <div className="group flex flex-col gap-1.5 rounded-xl border border-white/10 bg-white/[0.025] px-4 py-3 transition-colors hover:border-white/20 hover:bg-white/[0.05] sm:flex-row sm:items-center sm:gap-4">
      <span className={cn("w-14 shrink-0 rounded-md border px-2 py-0.5 text-center font-mono text-xs font-semibold", method === "POST" ? TONES.suspicious : TONES.safe)}>{method}</span>
      <code className="min-w-0 break-all font-mono text-[13px] text-zinc-200">{path}</code>
      <span className="text-[13px] text-muted-foreground sm:ml-auto sm:max-w-[45%] sm:text-right">{desc}</span>
    </div>
  );
}

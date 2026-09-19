import Link from "next/link";
import { TerminalBlock } from "@/components/terminal-block";
import { Reveal } from "@/components/reveal";
import { SpotlightCard } from "@/components/spotlight-card";
import { TerminalDemo, type DemoLine } from "@/components/home/terminal-demo";
import { DemoClockProvider } from "@/components/home/demo-clock";
import { Badge } from "@/components/ui/badge";
import { Terminal, Bot, ArrowRight } from "lucide-react";

// Real output of `npx pkgguard-cli install`, captured from the deployed API (same lines the CLI prints).
const CLI_DEMOS: DemoLine[][] = [
  [
    { text: "$ npx pkgguard-cli install express" },
    { text: "→ Resolved express → express@5.2.1", tone: "dim" },
    { text: "→ express@5.2.1: already scanned, from cache", tone: "dim" },
    { text: "  ✓ Threat intel  no match (OSV, SafeDep)", tone: "ok" },
    { text: "  ✓ Package info  no install scripts · 9 months old", tone: "ok" },
    { text: "  ✓ Static scan   7 files, 0 findings", tone: "ok" },
    { text: "  ✓ Sandbox       ran install + load in isolation, no secrets taken", tone: "ok" },
    { text: "  ✓ AI review     SAFE (high confidence)", tone: "ok" },
    { text: "✅ express@5.2.1 — SAFE (HIGH, ai): Express 5.2.1 is the legitimate web framework with no malicious code, install scripts, or suspicious behavior.", tone: "ok" },
    { text: "   Report: https://main.d37i3n9ev8lsz3.amplifyapp.com/npm/express?version=5.2.1", tone: "dim" },
    { text: "→ 1 package checked · 0 issues · 2.9s", tone: "dim" },
    { text: "" },
    { text: "Checked 1 package(s). 65 dependencies were not checked; add --deep to check them too.", tone: "dim" },
    { text: "" },
    { text: "Installing express@5.2.1 (exact, checked versions)...", tone: "dim" },
    { text: "✅ Installed.", tone: "ok" },
  ],
  [
    { text: "$ npx pkgguard-cli install cookie-validate" },
    { text: "→ Resolved cookie-validate → cookie-validate@2.2.4", tone: "dim" },
    { text: "→ cookie-validate@2.2.4: already scanned, from cache", tone: "dim" },
    { text: "  ✓ Threat intel  no match (OSV, SafeDep)", tone: "ok" },
    { text: "  ! Package info  postinstall script · 6 months old · 1 flag", tone: "warn" },
    { text: "  ! Static scan   4 files, 3 findings", tone: "warn" },
    { text: "  ✗ Sandbox       sent fake credentials to log-server-lovat.vercel.app", tone: "bad" },
    { text: "  ✗ AI review     MALICIOUS (high confidence)", tone: "bad" },
    { text: "🛑 cookie-validate@2.2.4 — MALICIOUS (HIGH, sandbox): Confirmed by running it in the sandbox: Sent planted fake credentials (npm token, github token, aws access key id, aws secret access key, openai api key, database url) to log-server-lovat.vercel.app.", tone: "bad" },
    { text: "   Report: https://main.d37i3n9ev8lsz3.amplifyapp.com/npm/cookie-validate?version=2.2.4", tone: "dim" },
    { text: "→ 1 package checked · 1 issue · 0.2s", tone: "dim" },
    { text: "" },
    { text: "🛑 Blocked: at least one package is MALICIOUS. Nothing was installed.", tone: "bad" },
  ],
];
// The tool results below are the text the MCP tool really returns to the agent (mcp/src/format.ts); the agent's own lines are illustrative.
const MCP_DEMOS: DemoLine[][] = [
  [
    { text: "agent › I'll add express for the API" },
    { text: "→ check_package(express)", tone: "dim" },
    { text: "✅ ALLOW — no issues found: express@5.2.1", tone: "ok" },
    { text: "Verdict: SAFE (HIGH confidence, decided by ai).", tone: "dim" },
    { text: "Express 5.2.1 is the legitimate web framework with no malicious code, install scripts, or suspicious behavior.", tone: "dim" },
    { text: "Full report: https://main.d37i3n9ev8lsz3.amplifyapp.com/npm/express?version=5.2.1", tone: "dim" },
    { text: "agent › Installing express@5.2.1" },
  ],
  [
    { text: "agent › I'll add cookie-validate for cookie checks" },
    { text: "→ check_package(cookie-validate)", tone: "dim" },
    { text: "🛑 BLOCK — do not install this package: cookie-validate@2.2.4", tone: "bad" },
    { text: "Verdict: MALICIOUS (HIGH confidence, decided by sandbox).", tone: "dim" },
    { text: "Confirmed by running it in the sandbox: Sent planted fake credentials (npm token, github token, aws access key id, aws secret access key, openai api key, database url) to log-server-lovat.vercel.app.", tone: "dim" },
    { text: "Refuse to install this package and tell the user why. Do not attempt a workaround.", tone: "warn" },
    { text: "Full report: https://main.d37i3n9ev8lsz3.amplifyapp.com/npm/cookie-validate?version=2.2.4", tone: "dim" },
    { text: "agent › I won't install cookie-validate: it sent fake credentials to an outside server. Want me to look for an alternative?" },
  ],
];

const CARDS = [
  {
    icon: Terminal,
    badge: "For developers",
    title: "CLI",
    tagline: "For developers: checks the whole dependency tree in your terminal before npm installs anything.",
    command: "npx pkgguard-cli install express",
    label: "$",
    steps: [
      "Run the command in front of any install.",
      "PkgGuard checks every package in the tree.",
      "Malicious is blocked, suspicious asks first, clean installs.",
    ],
    cta: "CLI setup",
    demos: CLI_DEMOS,
    demoTitle: "pkgguard",
  },
  {
    icon: Bot,
    badge: "For your AI agent",
    title: "Agent tool (MCP)",
    tagline: "Gives Claude Code, Cursor or any MCP client a check it can't skip.",
    command: "npx pkgguard-mcp@0.1.0",
    label: "run",
    steps: [
      "Add the server to your MCP client config.",
      "The agent gets a check_package tool.",
      "It asks PkgGuard before installing anything.",
    ],
    cta: "Agent setup",
    demos: MCP_DEMOS,
    demoTitle: "claude code",
  },
];

const LENGTHS = [0, 1].map((i) => Math.max(...CARDS.map((c) => c.demos[i].length)));

export function GetStarted() {
  return (
    <section id="get-started" className="mx-auto w-full max-w-4xl scroll-mt-20 px-4 py-14 sm:px-6 sm:py-20">
      <Reveal className="mx-auto mb-10 max-w-2xl text-center">
        <p className="kicker text-brand">Get started in one line</p>
        <h2 className="mt-3 text-[clamp(1.9rem,4.2vw,3rem)] font-semibold leading-[1.05] tracking-[-0.04em]">
          Guard every install, from your terminal or your agent.
        </h2>
      </Reveal>

      <DemoClockProvider lengths={LENGTHS} className="grid gap-5 md:grid-cols-2">
        {CARDS.map((c, idx) => (
          <Reveal key={c.title} delay={idx * 120}>
          <SpotlightCard beam className="h-full">
          <div className="flex h-full flex-col gap-3.5 p-4 sm:p-5">
            <div className="flex items-center justify-between">
              <span className="flex size-8 items-center justify-center rounded-lg border border-border bg-background">
                <c.icon className="size-4" />
              </span>
              <Badge variant="outline">{c.badge}</Badge>
            </div>
            <div className="flex flex-col gap-1.5">
              <h3 className="text-lg font-semibold tracking-tight">{c.title}</h3>
              <p className="text-[13px] leading-snug text-muted-foreground">{c.tagline}</p>
            </div>
            <TerminalBlock command={c.command} label={c.label} className="gap-2 px-3 py-2 text-[12.5px]" />
            <TerminalDemo scenarios={c.demos} title={c.demoTitle} />
            <ol className="flex flex-col gap-1.5">
              {c.steps.map((s, i) => (
                <li key={s} className="flex items-start gap-2.5 text-[13px] text-foreground/80">
                  <span className="mt-px flex size-4.5 shrink-0 items-center justify-center rounded-full border border-border font-mono text-[10px] text-muted-foreground">
                    {i + 1}
                  </span>
                  {s}
                </li>
              ))}
            </ol>
            <Link href="/docs" className="mt-auto inline-flex w-fit items-center gap-1 text-sm font-medium hover:underline">
              {c.cta} <ArrowRight className="size-3.5" />
            </Link>
          </div>
          </SpotlightCard>
          </Reveal>
        ))}
      </DemoClockProvider>
    </section>
  );
}

import Link from "next/link";
import { TerminalBlock } from "@/components/terminal-block";
import { Reveal } from "@/components/reveal";
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
    accent: "96,165,250",
    demos: CLI_DEMOS,
    demoTitle: "pkgguard",
  },
  {
    icon: Bot,
    badge: "For your AI agent",
    title: "Agent tool (MCP)",
    tagline: "Gives Claude Code, Cursor or any MCP client a check it can't skip.",
    command: "claude mcp add pkgguard -- npx -y pkgguard-mcp@0.1.1",
    label: "$",
    steps: [
      "Run the command once to add PkgGuard to Claude Code.",
      "Ask your agent to install a package as usual.",
      "It checks PkgGuard first: malicious is refused, clean goes ahead.",
    ],
    cta: "Agent setup",
    accent: "167,139,250",
    demos: MCP_DEMOS,
    demoTitle: "claude code",
  },
];

const LENGTHS = [0, 1].map((i) => Math.max(...CARDS.map((c) => c.demos[i].length)));

export function GetStarted() {
  return (
    <section id="get-started" data-snap className="mx-auto flex min-h-[100svh] w-full max-w-6xl scroll-mt-0 flex-col justify-center px-4 py-16 sm:px-8">
      <Reveal className="mx-auto mb-8 max-w-2xl text-center">
        <p className="kicker text-brand">Get started in one line</p>
        <h2 className="mt-3 text-[clamp(1.8rem,3.8vw,2.8rem)] font-semibold leading-[1.05] tracking-[-0.04em]">
          Guard every install, from your terminal or your agent.
        </h2>
      </Reveal>

      <DemoClockProvider lengths={LENGTHS} className="grid gap-5 lg:grid-cols-2">
        {CARDS.map((c, idx) => (
          <Reveal key={c.title} delay={idx * 120}>
            <div
              className="group relative h-full overflow-hidden rounded-3xl p-px transition-transform duration-500 hover:-translate-y-1"
              style={{ background: `linear-gradient(160deg, rgba(${c.accent},0.55), rgba(255,255,255,0.08) 35%, rgba(255,255,255,0.04) 70%, rgba(${c.accent},0.25))` }}
            >
              <div className="relative isolate flex h-full flex-col gap-3 overflow-hidden rounded-[calc(1.5rem-1px)] bg-[#06070a] p-4 sm:p-5">
                <div
                  aria-hidden
                  className="blob-drift pointer-events-none absolute -right-16 -top-20 -z-10 size-56 rounded-full blur-3xl"
                  style={{ background: `rgba(${c.accent},0.16)` }}
                />
                <div className="flex items-center gap-3">
                  <span
                    className="flex size-10 shrink-0 items-center justify-center rounded-xl border"
                    style={{ borderColor: `rgba(${c.accent},0.45)`, background: `rgba(${c.accent},0.12)`, color: `rgb(${c.accent})` }}
                  >
                    <c.icon className="size-5" />
                  </span>
                  <div className="min-w-0 flex-1">
                    <h3 className="text-lg font-semibold leading-tight tracking-tight">{c.title}</h3>
                    <p className="line-clamp-2 text-xs leading-snug text-muted-foreground">{c.tagline}</p>
                  </div>
                  <Badge variant="outline" className="hidden shrink-0 sm:inline-flex">{c.badge}</Badge>
                </div>

                <TerminalBlock command={c.command} label={c.label} wrap className="gap-3 px-4 py-3.5 text-[15px] leading-snug" />
                <TerminalDemo scenarios={c.demos} title={c.demoTitle} height={220} />

                <ol className="grid gap-2 sm:grid-cols-3">
                  {c.steps.map((st, i) => (
                    <li key={st} className="flex items-start gap-2 rounded-xl border border-white/8 bg-white/[0.03] p-2.5 text-[12px] leading-snug text-foreground/80 transition-colors group-hover:border-white/15">
                      <span
                        className="flex size-5 shrink-0 items-center justify-center rounded-full font-mono text-[10px] font-semibold"
                        style={{ background: `rgba(${c.accent},0.18)`, color: `rgb(${c.accent})` }}
                      >
                        {i + 1}
                      </span>
                      {st}
                    </li>
                  ))}
                </ol>

                <Link href="/docs" className="inline-flex w-fit items-center gap-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground">
                  {c.cta} <ArrowRight className="size-3.5" />
                </Link>
              </div>
            </div>
          </Reveal>
        ))}
      </DemoClockProvider>
    </section>
  );
}

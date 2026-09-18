import Link from "next/link";
import { TerminalBlock } from "@/components/terminal-block";
import { Reveal } from "@/components/reveal";
import { SpotlightCard } from "@/components/spotlight-card";
import { TerminalDemo, type DemoLine } from "@/components/home/terminal-demo";
import { Badge } from "@/components/ui/badge";
import { Terminal, Bot, ArrowRight } from "lucide-react";

const CLI_DEMO: DemoLine[] = [
  { text: "$ pkgguard install express left-pad-pro" },
  { text: "resolving dependency tree… 58 packages", tone: "dim" },
  { text: "✓ 57 packages: no issues found", tone: "ok" },
  { text: "✗ left-pad-pro@1.0.3 MALICIOUS", tone: "bad" },
  { text: "install blocked. nothing was installed.", tone: "warn" },
];
const MCP_DEMO: DemoLine[] = [
  { text: "agent › I'll add zod for validation" },
  { text: "→ check_package(zod@4.6.5)", tone: "dim" },
  { text: "✓ No issues found · 12ms", tone: "ok" },
  { text: "→ check_package(colors-js@2.1.0)", tone: "dim" },
  { text: "⚠ SUSPICIOUS: obfuscated postinstall", tone: "warn" },
  { text: "agent › skipping it, using picocolors", },
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
    demo: CLI_DEMO,
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
    demo: MCP_DEMO,
    demoTitle: "claude code",
  },
];

export function GetStarted() {
  return (
    <section id="get-started" className="mx-auto w-full max-w-5xl scroll-mt-20 px-4 py-16 sm:px-6 sm:py-24">
      <Reveal className="mx-auto mb-10 max-w-2xl text-center">
        <p className="kicker text-brand">Get started in one line</p>
        <h2 className="mt-3 text-[clamp(1.9rem,4.2vw,3rem)] font-semibold leading-[1.05] tracking-[-0.04em]">
          Guard every install, from your terminal or your agent.
        </h2>
      </Reveal>

      <div className="grid gap-5 md:grid-cols-2">
        {CARDS.map((c, idx) => (
          <Reveal key={c.title} delay={idx * 120}>
          <SpotlightCard beam className="h-full">
          <div className="flex h-full flex-col gap-5 p-6 sm:p-7">
            <div className="flex items-center justify-between">
              <span className="flex size-10 items-center justify-center rounded-lg border border-border bg-background">
                <c.icon className="size-5" />
              </span>
              <Badge variant="outline">{c.badge}</Badge>
            </div>
            <div className="flex flex-col gap-1.5">
              <h3 className="text-xl font-semibold tracking-tight">{c.title}</h3>
              <p className="text-sm text-muted-foreground">{c.tagline}</p>
            </div>
            <TerminalBlock command={c.command} label={c.label} />
            <TerminalDemo lines={c.demo} title={c.demoTitle} />
            <ol className="flex flex-col gap-2.5">
              {c.steps.map((s, i) => (
                <li key={s} className="flex items-start gap-3 text-sm text-foreground/80">
                  <span className="mt-0.5 flex size-5 shrink-0 items-center justify-center rounded-full border border-border font-mono text-[11px] text-muted-foreground">
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
      </div>
    </section>
  );
}

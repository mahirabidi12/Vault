import type { Metadata } from "next";
import type { ReactNode } from "react";
import { TerminalBlock } from "@/components/terminal-block";
import { ShieldCheck, Lock, Terminal, Bot, Globe } from "lucide-react";

export const metadata: Metadata = { title: "Docs" };

export default function DocsPage() {
  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-12 px-4 py-10 sm:px-6">
      <div className="flex flex-col gap-2">
        <h1 className="font-display text-2xl font-semibold tracking-tight">Docs</h1>
        <p className="text-sm text-muted-foreground">
          Everything you need to check packages from the command line, from an AI agent, or over the API.
        </p>
      </div>

      <div className="flex items-start gap-3 rounded-lg border border-safe/25 bg-safe-bg/60 p-5">
        <Lock className="mt-0.5 size-5 shrink-0 text-safe" />
        <div className="flex flex-col gap-1">
          <p className="text-sm font-semibold text-safe">Privacy</p>
          <p className="text-sm text-foreground/80">
            The CLI and agent tool send only package names and exact versions to PkgGuard — never your source
            code, environment variables, or the rest of your <code className="rounded bg-background/60 px-1 py-0.5 text-xs">package.json</code>.
            The project scan page parses your lockfile entirely in your browser.
          </p>
        </div>
      </div>

      <Section id="cli" icon={Terminal} title="CLI">
        <p className="text-sm text-muted-foreground">
          Nothing to set up. Run it in front of any install (Node.js 18 or newer). The first time, npx asks to
          download it. Answer <code className="rounded bg-muted px-1 py-0.5 text-xs">y</code>.
        </p>
        <TerminalBlock command="npx pkgguard-cli install express" />
        <p className="text-sm text-muted-foreground">
          Checks the packages you name, then blocks on anything <span className="font-medium text-malicious">malicious</span>,
          warns and asks to confirm on anything <span className="font-medium text-suspicious">suspicious</span>, and only then
          runs the real <code className="rounded bg-muted px-1 py-0.5 text-xs">npm install</code>, with the exact versions it
          checked. You see one line per check (threat intel, package info, static scan, sandbox, AI review), then the verdict.
        </p>
        <TerminalBlock command="npx pkgguard-cli install express --deep" />
        <p className="text-sm text-muted-foreground">
          <code className="rounded bg-muted px-1 py-0.5 text-xs">--deep</code> also checks every dependency of what you install.
          Packages nobody has scanned yet are scanned on the spot, so a big tree can take a few minutes the first time.
        </p>
        <TerminalBlock command="npx pkgguard-cli check lodash" />
        <p className="text-sm text-muted-foreground">
          Checks one package without installing it. Run <code className="rounded bg-muted px-1 py-0.5 text-xs">check</code> with
          no name inside a project to check every package in its lockfile. Add <code className="rounded bg-muted px-1 py-0.5 text-xs">--quiet</code> for
          just the verdict. Exit codes: 0 fine, 1 needs a look, 2 blocked, 3 could not finish.
        </p>
      </Section>

      <Section id="mcp" icon={Bot} title="Agent tool (MCP)">
        <p className="text-sm text-muted-foreground">
          Give any MCP-compatible agent (Claude Code, Cursor, …) a <code className="rounded bg-muted px-1 py-0.5 text-xs">check_package</code> tool
          it must call before installing anything. Pin the version — don&apos;t let the thing that checks your
          supply chain be an unchecked supply chain itself.
        </p>
        <TerminalBlock command="claude mcp add pkgguard -- npx -y pkgguard-mcp@0.1.1" label="$" />
        <p className="text-sm text-muted-foreground">Other MCP clients (Cursor etc.): use the config below.</p>
        <pre className="overflow-x-auto rounded-xl border border-border bg-muted/40 p-4 text-xs">
{`{
  "mcpServers": {
    "pkgguard": {
      "command": "npx",
      "args": ["-y", "pkgguard-mcp@0.1.1"]
    }
  }
}`}
        </pre>
      </Section>

      <Section id="api" icon={Globe} title="API">
        <p className="text-sm text-muted-foreground">
          The CLI, agent tool and website all call the same public API, at{" "}
          <code className="rounded bg-muted px-1 py-0.5 text-xs">https://632dcqt3l3.execute-api.ap-south-1.amazonaws.com</code>.
          No key is needed.
        </p>
        <div className="flex flex-col gap-2 font-mono text-xs">
          <ApiRow method="GET" path="/v1/package?ecosystem=npm&name=&version=" desc="Verdict, or 202 + scanId if not scanned yet" />
          <ApiRow method="POST" path="/v1/check" desc='Batch check — body: {"packages": [{ecosystem,name,version}]}, max 200 per request' />
          <ApiRow method="GET" path="/v1/report?ecosystem=npm&name=&version=" desc="Full report of a finished scan (exact version)" />
          <ApiRow method="GET" path="/v1/scans/{scanId}" desc="Poll a scan in progress" />
          <ApiRow method="GET" path="/v1/package/versions?ecosystem=npm&name=" desc="All scanned versions of a package" />
          <ApiRow method="GET" path="/v1/feed" desc="Recent malicious / suspicious verdicts" />
        </div>
        <p className="text-xs text-muted-foreground">
          Open for now, with no sign-up. Scanning a package nobody has checked before takes a minute or two, so
          the first lookup can answer 202 and you poll until it finishes. Personal API keys with quotas are planned.
        </p>
      </Section>

      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <ShieldCheck className="size-3.5" />
        A SAFE verdict means &quot;no issues found&quot; — not a guarantee.
      </div>
    </div>
  );
}

function Section({
  id,
  icon: Icon,
  title,
  children,
}: {
  id: string;
  icon: typeof Terminal;
  title: string;
  children: ReactNode;
}) {
  return (
    <section id={id} className="flex scroll-mt-24 flex-col gap-3">
      <h2 className="flex items-center gap-2 text-lg font-semibold tracking-tight">
        <Icon className="size-4.5 text-brand" />
        {title}
      </h2>
      {children}
    </section>
  );
}

function ApiRow({ method, path, desc }: { method: string; path: string; desc: string }) {
  return (
    <div className="flex flex-col gap-1 rounded-lg border border-border bg-card/50 px-3 py-2 sm:flex-row sm:items-center sm:gap-3">
      <span className="w-14 shrink-0 rounded bg-brand/10 px-1.5 py-0.5 text-center font-semibold text-brand">
        {method}
      </span>
      <span className="truncate">{path}</span>
      <span className="text-muted-foreground/70 sm:ml-auto">{desc}</span>
    </div>
  );
}

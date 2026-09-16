import type { Metadata } from "next";
import type { ReactNode } from "react";
import { TerminalBlock } from "@/components/terminal-block";
import { ShieldCheck, Lock, Terminal, Bot, Globe } from "lucide-react";

export const metadata: Metadata = { title: "Docs" };

export default function DocsPage() {
  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-12 px-4 py-10 sm:px-6">
      <div className="flex flex-col gap-2">
        <h1 className="text-2xl font-semibold tracking-tight">Docs</h1>
        <p className="text-sm text-muted-foreground">
          Everything you need to check packages from the command line, from an AI agent, or over the API.
        </p>
      </div>

      <div className="flex items-start gap-3 rounded-2xl border border-safe/25 bg-safe-bg/60 p-5">
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

      <Section icon={Terminal} title="CLI">
        <p className="text-sm text-muted-foreground">Install it, then use it in front of any install.</p>
        <TerminalBlock command="npm install -g pkgguard" />
        <TerminalBlock command="pkgguard install express @babel/core" />
        <p className="text-sm text-muted-foreground">
          Resolves your full dependency tree without installing anything, checks every package, then blocks
          on anything <span className="font-medium text-malicious">malicious</span>, warns and asks to confirm
          on anything <span className="font-medium text-suspicious">suspicious</span>, and only then runs the
          real <code className="rounded bg-muted px-1 py-0.5 text-xs">npm install</code>.
        </p>
        <TerminalBlock command="pkgguard check" label="$" />
        <p className="text-sm text-muted-foreground">Run inside a project to check an existing lockfile.</p>
      </Section>

      <Section icon={Bot} title="Agent tool (MCP)">
        <p className="text-sm text-muted-foreground">
          Give any MCP-compatible agent (Claude Code, Cursor, …) a <code className="rounded bg-muted px-1 py-0.5 text-xs">check_package</code> tool
          it must call before installing anything. Pin the version — don&apos;t let the thing that checks your
          supply chain be an unchecked supply chain itself.
        </p>
        <TerminalBlock command="npx pkgguard-mcp@1.0.0" />
        <pre className="overflow-x-auto rounded-xl border border-border bg-muted/40 p-4 text-xs">
{`{
  "mcpServers": {
    "pkgguard": {
      "command": "npx",
      "args": ["-y", "pkgguard-mcp@1.0.0"]
    }
  }
}`}
        </pre>
      </Section>

      <Section icon={Globe} title="API">
        <p className="text-sm text-muted-foreground">
          The CLI, agent tool and website all call the same public API.
        </p>
        <div className="flex flex-col gap-2 font-mono text-xs">
          <ApiRow method="GET" path="/v1/package?ecosystem=npm&name=&version=" desc="Verdict, or 202 + scanId if not scanned yet" />
          <ApiRow method="POST" path="/v1/check" desc="Batch check — body: [{ecosystem,name,version}]" />
          <ApiRow method="GET" path="/v1/scans/{scanId}" desc="Poll a scan in progress" />
          <ApiRow method="GET" path="/v1/package/versions?ecosystem=npm&name=" desc="All scanned versions of a package" />
          <ApiRow method="GET" path="/v1/feed" desc="Recent malicious / suspicious verdicts" />
        </div>
        <p className="text-xs text-muted-foreground">
          Anonymous lookups are allowed with strict rate limits. Sign up for an API key for higher limits
          (coming soon).
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
  icon: Icon,
  title,
  children,
}: {
  icon: typeof Terminal;
  title: string;
  children: ReactNode;
}) {
  return (
    <section className="flex flex-col gap-3">
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

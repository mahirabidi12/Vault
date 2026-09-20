"use client";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TerminalBlock } from "@/components/terminal-block";
import { CodeBlock } from "@/components/docs/code-block";

const CONFIG = `{
  "mcpServers": {
    "pkgguard": {
      "command": "npx",
      "args": ["-y", "pkgguard-mcp@0.1.2"]
    }
  }
}`;

export function McpTabs() {
  return (
    <Tabs defaultValue="claude" className="gap-4">
      <TabsList className="h-10 self-start">
        <TabsTrigger value="claude" className="px-4">Claude Code</TabsTrigger>
        <TabsTrigger value="others" className="px-4">Cursor and other clients</TabsTrigger>
      </TabsList>
      <TabsContent value="claude" className="flex flex-col gap-3">
        <p className="text-sm text-muted-foreground">Run this once. Claude Code adds PkgGuard and runs it for you from then on.</p>
        <TerminalBlock command="claude mcp add pkgguard -- npx -y pkgguard-mcp@0.1.2" label="$" wrap className="px-4 py-3.5 text-[14px]" />
      </TabsContent>
      <TabsContent value="others" className="flex flex-col gap-3">
        <p className="text-sm text-muted-foreground">Add this to your client&apos;s MCP config.</p>
        <CodeBlock code={CONFIG} lang="json" />
      </TabsContent>
    </Tabs>
  );
}

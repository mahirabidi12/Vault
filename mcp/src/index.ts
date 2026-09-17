#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { PkgGuardClient, loadConfig } from "./client.js";
import { registerCheckPackageTool } from "./tools/check-package.js";

const PACKAGE_VERSION = "0.1.0";

/** Loads ../.env (next to package.json) into process.env, without overriding real env vars. No .env file is fine. */
function loadDotEnv(): void {
  let text: string;
  try {
    text = readFileSync(new URL("../.env", import.meta.url), "utf8");
  } catch {
    return;
  }
  for (const line of text.split("\n")) {
    const match = /^\s*([\w.-]+)\s*=\s*(.*?)\s*$/.exec(line);
    if (!match || line.trim().startsWith("#")) continue;
    const [, key, rawValue] = match;
    if (key in process.env) continue;
    process.env[key] = rawValue.replace(/^(['"])(.*)\1$/, "$2");
  }
}

async function main(): Promise<void> {
  loadDotEnv();
  const config = loadConfig();
  if (!config.apiUrl) {
    console.error(
      "pkgguard-mcp: PKGGUARD_API_URL is not set. check_package will fail until it's configured " +
        "(cloud API URL once deployed, or http://127.0.0.1:8787 for `uv run pkgguard-dev-api`)."
    );
  }

  const client = new PkgGuardClient(config);
  const server = new McpServer({ name: "pkgguard-mcp", version: PACKAGE_VERSION });
  registerCheckPackageTool(server, client);

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((error) => {
  console.error("pkgguard-mcp failed to start:", error);
  process.exit(1);
});

#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";

import { PkgGuardClient, loadConfig } from "./client.js";
import { registerCheckPackageTool } from "./tools/check-package.js";

const PACKAGE_VERSION = "0.1.0";

async function main(): Promise<void> {
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

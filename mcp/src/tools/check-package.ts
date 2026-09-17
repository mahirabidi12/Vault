import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

import { PkgGuardClient, PkgGuardError } from "../client.js";
import { decide, formatText } from "../format.js";

const inputSchema = {
  name: z.string().min(1).max(214).describe("Exact npm package name, e.g. 'lodash' or '@babel/core'. Not a URL or a description."),
  version: z.string().optional().describe("Exact version to check, e.g. '4.17.21'. Omit to check the latest published version."),
  ecosystem: z.enum(["npm"]).optional().describe("Package ecosystem. Only 'npm' is supported today."),
};

const outputSchema = {
  recommendation: z.enum(["allow", "warn", "block", "wait"]).describe("What to do: allow, warn (confirm with the user first), block (refuse), or wait (scan still running)."),
  status: z.enum(["PENDING", "SCANNING", "COMPLETE", "FAILED", "SKIPPED"]),
  package: z.object({ ecosystem: z.literal("npm"), name: z.string(), version: z.string() }),
  verdict: z.enum(["SAFE", "SUSPICIOUS", "MALICIOUS"]).optional(),
  confidence: z.enum(["HIGH", "MEDIUM", "LOW"]).optional(),
  decidedBy: z.enum(["intel", "rules", "ai", "human"]).optional(),
  summary: z.string().optional(),
  signals: z.array(z.string()),
  scanId: z.string(),
  reportUrl: z.string().optional(),
  needsReview: z.boolean(),
  timedOut: z.boolean(),
};

export function registerCheckPackageTool(server: McpServer, client: PkgGuardClient): void {
  server.registerTool(
    "check_package",
    {
      title: "Check npm package safety",
      description:
        "Checks an npm package against PkgGuard's threat intelligence, static analysis and AI review before it " +
        "is installed, added to a manifest, or recommended to the user. Always call this before running " +
        "`npm install` / `pnpm add` / `yarn add`, or before editing package.json to add a dependency, for any " +
        "package you don't already have a fresh verdict for. Act on the result: BLOCK means refuse to install " +
        "and explain why; WARN means ask the user to confirm first; WAIT means call this again shortly instead " +
        "of installing; ALLOW means it's fine to proceed.",
      inputSchema,
      outputSchema,
      annotations: {
        title: "Check npm package safety",
        readOnlyHint: true,
        destructiveHint: false,
        openWorldHint: true,
      },
    },
    async ({ name, version }) => {
      try {
        const record = await client.checkPackage(name, version);
        const timedOut = record.status === "PENDING" || record.status === "SCANNING";
        const reportUrl = client.reportUrl(record.package.name, record.package.version);
        const result = decide(record, timedOut);
        return {
          content: [{ type: "text" as const, text: formatText(result, reportUrl) }],
          structuredContent: { ...result, reportUrl },
        };
      } catch (error) {
        const message =
          error instanceof PkgGuardError ? error.message : `Unexpected error checking "${name}": ${(error as Error).message}`;
        return {
          content: [
            {
              type: "text" as const,
              text:
                `Could not get a PkgGuard verdict for ${name}${version ? `@${version}` : ""}: ${message}\n` +
                "Treat this package as unverified — ask the user before installing.",
            },
          ],
          isError: true,
        };
      }
    }
  );
}

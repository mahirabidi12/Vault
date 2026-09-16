// Generates TypeScript types from the shared JSON Schemas in ../schema/.
// Run with `npm run gen:types`. Never hand-edit the output files.
import { compile } from "json-schema-to-typescript";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const schemaDir = path.resolve(__dirname, "../../schema");
const outDir = path.resolve(__dirname, "../src/lib/types");

const banner =
  "/**\n" +
  " * AUTO-GENERATED from schema/*.json. Do not edit by hand.\n" +
  " * Regenerate with `npm run gen:types` after the scanner agent updates the schema.\n" +
  " */\n\n";

async function generate(schemaFile, typeName, outFile) {
  const schema = JSON.parse(
    readFileSync(path.join(schemaDir, schemaFile), "utf-8")
  );
  const ts = await compile(schema, typeName, {
    bannerComment: "",
    additionalProperties: false,
    style: { semi: true, singleQuote: false },
  });
  mkdirSync(outDir, { recursive: true });
  writeFileSync(path.join(outDir, outFile), banner + ts);
  console.log(`wrote ${path.relative(process.cwd(), path.join(outDir, outFile))}`);
}

await generate("verdict-record.schema.json", "VerdictRecord", "verdict-record.ts");
await generate("report.schema.json", "Report", "report.ts");

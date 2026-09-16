const EXT_TO_LANG: Record<string, string> = {
  js: "javascript",
  cjs: "javascript",
  mjs: "javascript",
  jsx: "jsx",
  ts: "typescript",
  tsx: "tsx",
  json: "json",
  sh: "bash",
  bash: "bash",
  ps1: "powershell",
  py: "python",
  bat: "batch",
  yml: "yaml",
  yaml: "yaml",
  md: "markdown",
  yar: "text",
};

export function langForFile(file: string | null | undefined): string {
  if (!file) return "text";
  const base = file.split("/").pop() ?? file;
  if (base === "package.json") return "json";
  const ext = base.includes(".") ? base.split(".").pop()! : "";
  return EXT_TO_LANG[ext.toLowerCase()] ?? "text";
}

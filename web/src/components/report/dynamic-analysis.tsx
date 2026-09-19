import {
  AlertTriangle,
  ArrowRightLeft,
  Box,
  Clock,
  FileText,
  Globe,
  GitBranch,
  KeyRound,
  Lock,
  Network,
  ShieldAlert,
  SquareTerminal,
  Timer,
} from "lucide-react";
import { CodeEvidence } from "@/components/code-evidence";
import { SeverityBadge } from "@/components/verdict-ui";
import { cn } from "@/lib/utils";
import {
  FILE_GROUP_LABEL,
  classificationInfo,
  coverageGaps,
  coverageLine,
  groupFiles,
  hasProof,
  hostileOnlyHosts,
  opLabel,
  processTree,
  runLabel,
  runsLabel,
  runsPresent,
  sandboxStage,
  sortedNetwork,
  statusHeadline,
  type Tone,
} from "@/lib/sandbox";
import type { SandboxReport, VerdictRecord } from "@/lib/types/domain";

const TONE_TEXT: Record<Tone, string> = {
  ok: "text-safe",
  warn: "text-suspicious",
  bad: "text-malicious",
  muted: "text-muted-foreground",
};
const TONE_CHIP: Record<Tone, string> = {
  ok: "border-safe/30 bg-safe/10 text-safe",
  warn: "border-suspicious/30 bg-suspicious/10 text-suspicious",
  bad: "border-malicious/40 bg-malicious/10 text-malicious",
  muted: "border-white/10 bg-white/5 text-muted-foreground",
};

export async function DynamicAnalysis({ sandbox, record }: { sandbox?: SandboxReport | null; record: VerdictRecord }) {
  if (!sandbox || sandbox.status === "NOT_RUN") {
    return (
      <section id="dynamic-analysis" className="flex items-center gap-4 rounded-3xl border border-dashed border-white/15 bg-white/[0.02] p-6">
        <span className="flex size-11 shrink-0 items-center justify-center rounded-xl border border-white/10 bg-white/5">
          <Box className="size-5 text-muted-foreground" />
        </span>
        <div>
          <h2 className="font-display text-lg font-semibold">Dynamic analysis: not run</h2>
          <p className="text-sm text-muted-foreground">
            This scan has no runtime recording. Packages scanned before the sandbox existed, or where it could not start, look like this.
          </p>
        </div>
      </section>
    );
  }

  const stage = sandboxStage(sandbox);
  const gaps = coverageGaps(sandbox);
  const confirmed = record.decidedBy === "sandbox";
  const proof = hasProof(sandbox);
  const network = sortedNetwork(sandbox);
  const files = groupFiles(sandbox);
  const runs = runsPresent(sandbox);
  const onlyHostile = hostileOnlyHosts(sandbox);
  const quiet =
    network.length === 0 &&
    (sandbox.files ?? []).length === 0 &&
    (sandbox.evalPayloads ?? []).length === 0 &&
    (sandbox.findings ?? []).length === 0;

  return (
    <section id="dynamic-analysis" className="relative isolate flex flex-col gap-8 overflow-hidden rounded-3xl border border-white/10 bg-white/[0.02] p-6 sm:p-8">
      <div aria-hidden className="pointer-events-none absolute -right-20 -top-24 -z-10 size-80 rounded-full bg-brand/10 blur-3xl" />

      {/* header */}
      <header className="flex flex-col gap-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex items-center gap-3">
            <span className="flex size-12 items-center justify-center rounded-2xl border border-white/10 bg-white/[0.05]">
              <Box className="size-6" />
            </span>
            <div>
              <p className="kicker text-brand">Dynamic analysis</p>
              <h2 className="font-display text-2xl font-semibold tracking-tight sm:text-3xl">What it did when we ran it</h2>
            </div>
          </div>
          {confirmed && (
            <span className="inline-flex items-center gap-2 rounded-full border border-malicious/50 bg-malicious/10 px-4 py-2 text-sm font-semibold text-malicious">
              <ShieldAlert className="size-4" />
              Confirmed by sandbox run
            </span>
          )}
        </div>

        <p className="max-w-3xl text-[15px] leading-relaxed text-muted-foreground">
          The package was installed and run inside a locked box with no internet, with fake passwords and keys planted for it to find. Everything below is what it really tried to do, not a guess from reading the code.
        </p>

        <div className="flex flex-wrap items-center gap-2.5">
          <Chip tone={stage.tone} icon={Box}>
            {statusHeadline(sandbox)}
          </Chip>
          <Chip tone="muted" icon={Timer}>
            {sandbox.durationSeconds?.toFixed(1)} s
          </Chip>
          <Chip tone="muted" icon={Network}>
            {coverageLine(sandbox)}
          </Chip>
          {(sandbox.findings ?? []).map((f, i) => (
            <span
              key={`${f.ruleId}-${i}`}
              className={cn("inline-flex items-center gap-1.5 rounded-full border px-3 py-1 font-mono text-xs", f.severity === "HIGH" ? TONE_CHIP.bad : f.severity === "MEDIUM" ? TONE_CHIP.warn : TONE_CHIP.muted)}
            >
              {f.ruleId}
              <SeverityBadge severity={f.severity} className="ml-0.5" />
            </span>
          ))}
        </div>

        {gaps.length > 0 && (
          <div className="flex gap-3 rounded-2xl border border-suspicious/30 bg-suspicious/[0.07] p-4">
            <AlertTriangle className="mt-0.5 size-5 shrink-0 text-suspicious" />
            <div className="text-sm">
              <p className="font-semibold text-suspicious">Not everything could be observed</p>
              <ul className="mt-1 list-disc space-y-0.5 pl-5 text-foreground/80">
                {gaps.map((g) => (
                  <li key={g}>{g}</li>
                ))}
              </ul>
              {quiet && <p className="mt-2 text-muted-foreground">A quiet recording here means we saw nothing, not that nothing can happen.</p>}
            </div>
          </div>
        )}
      </header>

      {/* proof of exfiltration */}
      {(sandbox.canaryHits ?? []).length > 0 && (
        <div className="threat-box rounded-2xl border border-malicious/50 bg-malicious/[0.07] p-5">
          <p className="flex items-center gap-2 text-lg font-semibold text-malicious">
            <KeyRound className="size-5" />
            Carried your fake credentials out
          </p>
          <p className="mt-1 text-sm text-foreground/80">
            These planted values are fake and unique to this run. Seeing one in an outgoing request is proof of theft, not a hunch.
          </p>
          <ul className="mt-3 flex flex-wrap gap-2">
            {sandbox.canaryHits!.map((c, i) => (
              <li key={`${c.canaryId}-${i}`} className="rounded-lg border border-malicious/30 bg-black/40 px-3 py-1.5 font-mono text-xs">
                <span className="text-malicious">{c.canaryId}</span>
                <span className="text-muted-foreground"> → {c.sink}</span>
                <span className="ml-2 text-muted-foreground/70">{runLabel(c.run)}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* run A vs run B */}
      {(sandbox.runs ?? []).length > 0 && (
        <div className="flex flex-col gap-3">
          <SubHead icon={ArrowRightLeft}>Normal conditions vs hostile conditions</SubHead>
          <div className="grid gap-3 md:grid-cols-2">
            {sandbox.runs!.map((r) => {
              const net = (sandbox.network ?? []).filter((n) => n.run === r.name).length;
              const procs = (sandbox.processes ?? []).filter((p) => p.run === r.name).length;
              const fl = (sandbox.files ?? []).filter((f) => f.run === r.name).length;
              return (
                <div key={r.name} className="flex flex-col gap-3 rounded-2xl border border-white/10 bg-white/[0.03] p-5">
                  <p className="font-display text-lg font-semibold">{runLabel(r.name)}</p>
                  <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
                    <Kv k="CI environment" v={r.ci ? "on (looks like a CI runner)" : "off"} />
                    <Kv k="Clock" v={r.clockOffsetDays ? `+${r.clockOffsetDays} days` : "real time"} />
                    <Kv k="Hostname" v={r.hostname ?? "—"} mono />
                    <Kv k="User" v={r.user ?? "—"} mono />
                  </dl>
                  <div className="flex flex-wrap gap-2 text-xs">
                    {(r.phases ?? []).map((p) => (
                      <span key={p.name} className="inline-flex items-center gap-1.5 rounded-md border border-white/10 bg-black/30 px-2 py-1 font-mono">
                        <Clock className="size-3" />
                        {p.name} {p.seconds?.toFixed(1)}s
                        <span className={p.timedOut ? "text-suspicious" : (p.exitCode ?? 0) === 0 ? "text-safe" : "text-malicious"}>
                          {p.timedOut ? "timeout" : `exit ${p.exitCode ?? "?"}`}
                        </span>
                      </span>
                    ))}
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {net} network event{net !== 1 ? "s" : ""} · {procs} process{procs !== 1 ? "es" : ""} · {fl} file change{fl !== 1 ? "s" : ""}
                  </p>
                </div>
              );
            })}
          </div>
          {((sandbox.conditional ?? []).length > 0 || onlyHostile.length > 0) && (
            <div className="rounded-2xl border border-malicious/40 bg-malicious/[0.07] p-4 text-sm">
              <p className="flex items-center gap-2 font-semibold text-malicious">
                <GitBranch className="size-4" />
                Only appears under hostile conditions
              </p>
              <p className="mt-1 text-foreground/80">
                A package that behaves differently when it thinks it is in CI, or on a later date, is trying not to be caught. That is a strong sign of malice.
              </p>
              <ul className="mt-2 list-disc space-y-0.5 pl-5">
                {(sandbox.conditional ?? []).map((c, i) => (
                  <li key={i}>{c.description}</li>
                ))}
                {(sandbox.conditional ?? []).length === 0 &&
                  onlyHostile.map((h) => (
                    <li key={h}>
                      Contacts <span className="font-mono">{h}</span> only in run B
                    </li>
                  ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {quiet && gaps.length === 0 && (
        <div className="rounded-2xl border border-safe/25 bg-safe/[0.06] p-5 text-sm">
          <p className="font-semibold text-safe">Nothing suspicious observed</p>
          <p className="mt-1 text-foreground/80">No network calls, no file changes outside the package and no decoded code were seen in either run. This is not a guarantee.</p>
        </div>
      )}

      {/* network timeline */}
      {network.length > 0 && (
        <div className="flex flex-col gap-3">
          <SubHead icon={Globe}>Network timeline</SubHead>
          <p className="text-sm text-muted-foreground">There is no real internet in the box. A fake DNS and web server answered, so we could see every name and request it tried.</p>
          <ol className="relative flex flex-col gap-2.5 border-l border-white/10 pl-5">
            {network.map((n, i) => {
              const cls = classificationInfo(n.classification);
              const target = n.url ?? (n.host ? `${n.host}${n.port ? `:${n.port}` : ""}` : `${n.ip}${n.port ? `:${n.port}` : ""}`);
              return (
                <li key={i} className="relative">
                  <span
                    aria-hidden
                    className={cn("absolute -left-[27px] top-3 size-3 rounded-full border-2 border-black", n.canaryHit ? "bg-malicious shadow-[0_0_10px_var(--malicious)]" : cls.tone === "bad" ? "bg-malicious" : cls.tone === "warn" ? "bg-suspicious" : "bg-zinc-500")}
                  />
                  <div className={cn("flex flex-col gap-2 rounded-xl border p-3.5", n.canaryHit ? "border-malicious/40 bg-malicious/[0.06]" : "border-white/10 bg-white/[0.03]")}>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="rounded-md border border-white/10 bg-black/40 px-2 py-0.5 font-mono text-[11px] font-semibold uppercase">{n.kind}</span>
                      {n.method && <span className="font-mono text-xs text-muted-foreground">{n.method}</span>}
                      <span className="break-all font-mono text-sm">{target}</span>
                      {(n.count ?? 1) > 1 && <span className="text-xs text-muted-foreground">× {n.count}</span>}
                      <span className={cn("ml-auto rounded-full border px-2.5 py-0.5 text-xs font-medium", TONE_CHIP[cls.tone])}>{cls.label}</span>
                    </div>
                    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
                      <span>{runLabel(n.run)}</span>
                      {n.phase && <span>during {n.phase}</span>}
                      {n.canaryHit && (
                        <span className="inline-flex items-center gap-1 font-semibold text-malicious">
                          <KeyRound className="size-3.5" />
                          Carried your fake credentials
                        </span>
                      )}
                    </div>
                    {n.bodyPreview && <CodeEvidence file="request body" snippet={n.bodyPreview} tone={n.canaryHit ? "threat" : "neutral"} />}
                  </div>
                </li>
              );
            })}
          </ol>
        </div>
      )}

      {/* processes */}
      {(sandbox.processes ?? []).length > 0 && (
        <div className="flex flex-col gap-3">
          <SubHead icon={SquareTerminal}>Processes it started</SubHead>
          <div className="grid gap-3 lg:grid-cols-2">
            {runs.map((run) => {
              const tree = processTree(sandbox, run);
              if (tree.length === 0) return null;
              return (
                <div key={run} className="rounded-2xl border border-white/10 bg-black/30 p-4">
                  <p className="mb-2 text-sm font-semibold">{runLabel(run)}</p>
                  <ul className="flex flex-col gap-1 font-mono text-[13px]">
                    {tree.map(({ proc, depth }) => (
                      <li key={proc.pid} className="flex items-baseline gap-2" style={{ paddingLeft: depth * 18 }}>
                        <span className="text-muted-foreground/60">{depth > 0 ? "└" : "▸"}</span>
                        <span className="break-all">{proc.argv?.length ? proc.argv.join(" ") : proc.exe}</span>
                        {proc.phase && <span className="shrink-0 text-[11px] text-muted-foreground">{proc.phase}</span>}
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* files */}
      {files.length > 0 && (
        <div className="flex flex-col gap-4">
          <SubHead icon={FileText}>File activity</SubHead>
          {files.map((g) => (
            <div key={g.id} className="flex flex-col gap-2.5">
              <p className={cn("flex items-center gap-2 text-sm font-semibold", g.id === "persistence" ? "text-malicious" : g.id === "dropped" ? "text-suspicious" : g.id === "decoy" ? "text-suspicious" : "text-muted-foreground")}>
                {g.id === "persistence" && <Lock className="size-4" />}
                {FILE_GROUP_LABEL[g.id]}
              </p>
              {g.files.map((f, i) => (
                <div key={i} className={cn("flex flex-col gap-2 rounded-xl border p-3.5", g.id === "persistence" ? "border-malicious/40 bg-malicious/[0.06]" : "border-white/10 bg-white/[0.03]")}>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-md border border-white/10 bg-black/40 px-2 py-0.5 text-xs">{opLabel(f.op)}</span>
                    <span className="break-all font-mono text-sm">{f.path}</span>
                    {f.decoy && <span className="rounded-full border border-suspicious/30 bg-suspicious/10 px-2 py-0.5 text-xs text-suspicious">fake credential</span>}
                    {f.executable && <span className="rounded-full border border-suspicious/30 bg-suspicious/10 px-2 py-0.5 text-xs text-suspicious">made executable</span>}
                    <span className="ml-auto text-xs text-muted-foreground">{runsLabel(f.runs)}</span>
                  </div>
                  {f.sha256 && <p className="break-all font-mono text-[11px] text-muted-foreground">sha256 {f.sha256}</p>}
                  {f.preview && <CodeEvidence file={f.path} snippet={f.preview} tone={g.id === "persistence" ? "threat" : g.id === "dropped" ? "warn" : "neutral"} />}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {/* decoded payloads */}
      {(sandbox.evalPayloads ?? []).length > 0 && (
        <div className="flex flex-col gap-3">
          <SubHead icon={FileText}>Code it decoded and ran</SubHead>
          <p className="text-sm text-muted-foreground">Hidden code is caught at the moment it reaches eval, so this is the real text, not the scrambled version in the file.</p>
          {sandbox.evalPayloads!.map((e, i) => (
            <div key={i} className="flex flex-col gap-2">
              <p className="font-mono text-xs text-muted-foreground">
                {e.api} · {e.length} bytes · {runLabel(e.run)} · sha256 {e.sha256.slice(0, 16)}…
              </p>
              <CodeEvidence file={`decoded via ${e.api}`} snippet={e.preview} tone="warn" />
            </div>
          ))}
        </div>
      )}

      {/* footer */}
      <p className="border-t border-white/10 pt-4 text-xs text-muted-foreground">
        Peak {sandbox.resources?.peakMemoryMb?.toFixed(0)} MB memory, {sandbox.resources?.peakCpuSeconds?.toFixed(1)} s CPU. Sandbox v{sandbox.version}
        {proof ? " · proof-grade evidence: the AI cannot clear this." : ""}
      </p>
    </section>
  );
}

function Chip({ tone, icon: Icon, children }: { tone: Tone; icon: typeof Box; children: React.ReactNode }) {
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm font-medium", TONE_CHIP[tone])}>
      <Icon className={cn("size-4", TONE_TEXT[tone])} />
      {children}
    </span>
  );
}

function SubHead({ icon: Icon, children }: { icon: typeof Box; children: React.ReactNode }) {
  return (
    <h3 className="flex items-center gap-2 font-display text-lg font-semibold tracking-tight">
      <Icon className="size-5 text-muted-foreground" />
      {children}
    </h3>
  );
}

function Kv({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <>
      <dt className="text-muted-foreground">{k}</dt>
      <dd className={cn("truncate", mono && "font-mono text-[13px]")}>{v}</dd>
    </>
  );
}

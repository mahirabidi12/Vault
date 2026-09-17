"""Splits a package's code into worker-sized chunks: skips junk and duplicates, most important files first."""

import hashlib
from dataclasses import dataclass, field
from pathlib import Path

from pkgguard_analyzer.code_scan.files import PATTERN_EXTENSIONS
from pkgguard_analyzer.schema import Finding, SkippedFile

SKIP_SUFFIXES = (".d.ts", ".d.mts", ".d.cts", ".map")
MAX_AUDIT_CHARS = 3_000_000
CHUNK_CHARS = 80_000
LINE_SEGMENT_CHARS = 2_000
BINARY_SNIFF_BYTES = 8_000
MAX_REPORTED_SKIPS = 100


@dataclass
class AuditFile:
    path: str
    text: str
    labels: list[str]


@dataclass
class Chunk:
    index: int
    text: str
    files: list[str] = field(default_factory=list)


@dataclass
class AuditPlan:
    chunks: list[Chunk]
    files_total: int
    files_analyzed: int
    bytes_total: int
    bytes_analyzed: int
    duplicates_skipped: int
    skipped: list[SkippedFile]

    @property
    def skipped_for_report(self) -> list[SkippedFile]:
        return self.skipped[:MAX_REPORTED_SKIPS]


def _candidate(relative: str, special: set[str]) -> bool:
    if relative.endswith(SKIP_SUFFIXES):
        return False
    return Path(relative).suffix.lower() in PATTERN_EXTENSIONS or relative == "package.json" or relative in special


def plan_audit(
    files_dir: Path,
    code_scan: dict,
    findings: list[Finding],
    max_chars: int = MAX_AUDIT_CHARS,
    chunk_chars: int = CHUNK_CHARS,
) -> AuditPlan:
    install_files = set(code_scan.get("installTimeFiles", []))
    entry_files = set(code_scan.get("entryFiles", []))
    flagged_files = {f.file for f in findings if f.file}
    special = install_files | entry_files

    paths = sorted(p.relative_to(files_dir).as_posix() for p in files_dir.rglob("*") if p.is_file())
    candidates = [path for path in paths if _candidate(path, special)]
    candidate_set = set(candidates)

    def priority(path: str) -> tuple:
        return (path != "package.json", path not in install_files, path not in entry_files, path not in flagged_files, path)

    skipped: list[SkippedFile] = []
    selected: list[AuditFile] = []
    seen_hashes: set[str] = set()
    duplicates = bytes_total = bytes_analyzed = used_chars = 0

    for path in sorted(candidates, key=priority):
        data = (files_dir / path).read_bytes()
        bytes_total += len(data)
        if b"\x00" in data[:BINARY_SNIFF_BYTES]:
            skipped.append(SkippedFile(path=path, reason="binary"))
            continue
        if path.endswith(".min.js") and path[: -len(".min.js")] + ".js" in candidate_set:
            skipped.append(SkippedFile(path=path, reason="minified copy of another file"))
            continue
        digest = hashlib.sha256(data).hexdigest()
        if digest in seen_hashes:
            duplicates += 1
            skipped.append(SkippedFile(path=path, reason="exact duplicate of another file"))
            continue
        text = data.decode("utf-8", "replace")
        if used_chars + len(text) > max_chars:
            skipped.append(SkippedFile(path=path, reason="audit size limit reached"))
            continue
        seen_hashes.add(digest)
        used_chars += len(text)
        bytes_analyzed += len(data)
        labels = [label for label, members in (("runs at install time", install_files), ("runs on import", entry_files), ("flagged by rules", flagged_files)) if path in members]
        selected.append(AuditFile(path, text, labels))

    return AuditPlan(
        chunks=pack_chunks(selected, chunk_chars),
        files_total=len(candidates),
        files_analyzed=len(selected),
        bytes_total=bytes_total,
        bytes_analyzed=bytes_analyzed,
        duplicates_skipped=duplicates,
        skipped=skipped,
    )


def render_lines(text: str) -> list[str]:
    """Numbered lines. Very long lines (minified code) are split into segments numbered 12.1, 12.2, ..."""
    rendered = []
    for number, line in enumerate(text.split("\n"), 1):
        if len(line) <= LINE_SEGMENT_CHARS:
            rendered.append(f"{number:>6}| {line}")
            continue
        for part, start in enumerate(range(0, len(line), LINE_SEGMENT_CHARS), 1):
            rendered.append(f"{number:>4}.{part}| {line[start : start + LINE_SEGMENT_CHARS]}")
    return rendered


def pack_chunks(files: list[AuditFile], chunk_chars: int = CHUNK_CHARS) -> list[Chunk]:
    chunks: list[Chunk] = []
    lines: list[str] = []
    names: list[str] = []
    size = 0

    def flush() -> None:
        nonlocal lines, names, size
        if lines:
            chunks.append(Chunk(index=len(chunks), text="\n".join(lines), files=names))
        lines, names, size = [], [], 0

    def emit(line: str, file: str) -> None:
        nonlocal size
        lines.append(line)
        size += len(line) + 1
        if file not in names:
            names.append(file)

    for audit_file in files:
        labels = f" [{', '.join(audit_file.labels)}]" if audit_file.labels else ""
        body = render_lines(audit_file.text)
        emit(f"===== FILE: {audit_file.path}{labels} ({audit_file.text.count(chr(10)) + 1} lines) =====", audit_file.path)
        for line in body:
            if size + len(line) + 1 > chunk_chars and size > 0:
                flush()
                emit(f"===== FILE: {audit_file.path} (continued) =====", audit_file.path)
            emit(line, audit_file.path)
    flush()
    return chunks

"""Picks which files to scan and marks the ones that run at install time or on import."""

import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from pkgguard_analyzer.metadata_checks import install_scripts

AST_EXTENSIONS = frozenset({".js", ".cjs", ".mjs", ".jsx"})
PATTERN_EXTENSIONS = AST_EXTENSIONS | frozenset(
    {".ts", ".tsx", ".mts", ".cts", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd", ".py"}
)
DECLARATION_SUFFIXES = (".d.ts", ".d.mts", ".d.cts")
MAX_AST_BYTES = 1_000_000
MAX_PATTERN_BYTES = 20_000_000
MAX_CODE_FILES = 5_000
EXECUTABLE_MAGIC = (
    (b"\x7fELF", "Linux executable"),
    (b"\xcf\xfa\xed\xfe", "macOS executable"),
    (b"\xce\xfa\xed\xfe", "macOS executable"),
    (b"\xca\xfe\xba\xbe", "macOS universal binary"),
    (b"MZ", "Windows executable"),
)
NODE_COMMAND_RE = re.compile(r"\bnode\s+(?:-{1,2}[\w-]+(?:=\S+)?\s+)*([\w./@-]+)")


@dataclass
class CodeFile:
    path: str
    full_path: Path
    size: int
    parse_ast: bool
    install_time: bool
    entry: bool


@dataclass
class FileSelection:
    code_files: list[CodeFile] = field(default_factory=list)
    executables: list[tuple[str, str]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)


def _candidates(target: str) -> set[str]:
    path = str(PurePosixPath(target.removeprefix("./")))
    if PurePosixPath(path).suffix:
        return {path}
    return {path, f"{path}.js", f"{path}/index.js"}


def install_time_targets(scripts: dict[str, str]) -> set[str]:
    """Files run by install scripts, e.g. "node ./scripts/postinstall.js"."""
    targets: set[str] = set()
    for command in scripts.values():
        for match in NODE_COMMAND_RE.finditer(command):
            targets |= _candidates(match.group(1))
    return targets


def _export_paths(exports: object, depth: int = 0) -> list[str]:
    if depth > 3:
        return []
    if isinstance(exports, str):
        return [exports]
    if isinstance(exports, dict):
        # "." is the main export; other "./subpath" keys are optional entry points, condition keys wrap paths.
        return [
            path
            for key, value in exports.items()
            if key == "." or not key.startswith(".")
            for path in _export_paths(value, depth + 1)
        ]
    return []


def entry_targets(manifest: dict) -> set[str]:
    """Files that run when the package is imported or its CLI is used."""
    main = manifest.get("main")
    values = [main if isinstance(main, str) and main else "index.js"]
    bin_field = manifest.get("bin")
    if isinstance(bin_field, str):
        values.append(bin_field)
    elif isinstance(bin_field, dict):
        values += [v for v in bin_field.values() if isinstance(v, str)]
    values += _export_paths(manifest.get("exports"))
    targets: set[str] = set()
    for value in values:
        targets |= _candidates(value)
    return targets


def _executable_kind(path: Path) -> str | None:
    with path.open("rb") as handle:
        head = handle.read(4)
    return next((kind for magic, kind in EXECUTABLE_MAGIC if head.startswith(magic)), None)


def select_files(files_dir: Path, manifest: dict) -> FileSelection:
    install_targets = install_time_targets(install_scripts(manifest))
    entries = entry_targets(manifest)
    selection = FileSelection()

    for full_path in sorted(p for p in files_dir.rglob("*") if p.is_file()):
        relative = full_path.relative_to(files_dir).as_posix()
        if kind := _executable_kind(full_path):
            selection.executables.append((relative, kind))
            continue

        install_time = relative in install_targets
        entry = relative in entries
        suffix = full_path.suffix.lower()
        recognized = suffix in PATTERN_EXTENSIONS and not relative.endswith(DECLARATION_SUFFIXES)
        if not (recognized or install_time or entry):
            continue

        size = full_path.stat().st_size
        if size > MAX_PATTERN_BYTES:
            selection.skipped.append({"path": relative, "reason": "file too large"})
            continue
        javascript = suffix in AST_EXTENSIONS or ((install_time or entry) and suffix == "")
        selection.code_files.append(
            CodeFile(relative, full_path, size, javascript and size <= MAX_AST_BYTES, install_time, entry)
        )

    selection.code_files.sort(key=lambda f: (not f.install_time, not f.entry, f.path))
    for extra in selection.code_files[MAX_CODE_FILES:]:
        selection.skipped.append({"path": extra.path, "reason": "file limit reached"})
    del selection.code_files[MAX_CODE_FILES:]
    return selection

"""Read-only, budgeted access to one unpacked package for the AI agent.

Everything returned is wrapped in <package_content> tags: it is attacker-controlled data, not instructions.
"""

import re
import time
from pathlib import Path, PurePosixPath

from pkgguard_analyzer.schema import ToolCall

MAX_LINES_PER_READ = 300
MAX_LINE_CHARS = 400
MAX_LISTED_FILES = 300
MAX_SEARCH_RESULTS = 40
MAX_SEARCH_FILE_BYTES = 20_000_000
SEARCH_WINDOW_CHARS = 200
BINARY_SNIFF_BYTES = 8_000
BUDGET_EXHAUSTED = "Tool budget used up. Stop investigating and give your final assessment now."
CLOSING_TAG = "</package_content"


def wrap_untrusted(content: str, **attributes: object) -> str:
    # Stop package content from closing our wrapper and "escaping" into instructions.
    safe = content.replace(CLOSING_TAG, "<\\/package_content")
    attrs = " ".join(f'{key}="{value}"' for key, value in attributes.items())
    return f"<package_content {attrs}>\n{safe}\n</package_content>"


class PackageWorkspace:
    def __init__(self, root: Path, max_tool_calls: int, labels: dict[str, str] | None = None):
        self.root = root.resolve()
        self.max_tool_calls = max_tool_calls
        self.labels = labels or {}
        self.tool_calls = 0
        self.files_read: list[str] = []
        self.trace: list[ToolCall] = []

    def _traced(self, tool: str, arguments: dict[str, str | int], run) -> str:
        started = time.monotonic()
        if not self._charge():
            output, outcome = BUDGET_EXHAUSTED, "budget_exhausted"
        else:
            output = run()
            if output.startswith("File not found"):
                outcome = "not_found"
            elif "binary file" in output[:200]:
                outcome = "binary"
            elif output.startswith(("No matches", "No files found")) or " has only " in output[:200]:
                outcome = "empty"
            else:
                outcome = "ok"
            output = self._with_budget(output)
        self.trace.append(
            ToolCall(step=len(self.trace) + 1, tool=tool, arguments=arguments, outcome=outcome, result_chars=len(output), seconds=round(time.monotonic() - started, 3))
        )
        return output

    def _charge(self) -> bool:
        """Count a tool call if budget remains. Refused calls aren't counted."""
        if self.tool_calls >= self.max_tool_calls:
            return False
        self.tool_calls += 1
        return True

    def _with_budget(self, output: str) -> str:
        remaining = self.max_tool_calls - self.tool_calls
        note = "no tool calls left: give your final assessment now" if remaining == 0 else f"{remaining} tool calls left"
        return f"{output}\n[{note}]"

    def resolve(self, path: str) -> Path | None:
        """Map an agent-supplied path to a real file inside the package, or None."""
        candidate = PurePosixPath(path.strip())
        if not path.strip() or candidate.is_absolute() or ".." in candidate.parts:
            return None
        target = (self.root / candidate).resolve()
        return target if target.is_relative_to(self.root) and target.is_file() else None

    def exists(self, path: str) -> bool:
        return self.resolve(path) is not None

    def _relative(self, target: Path) -> str:
        return target.relative_to(self.root).as_posix()

    def _files_under(self, directory: str) -> list[Path]:
        base = self.root if not directory.strip() else (self.root / directory.strip().strip("/")).resolve()
        if not base.is_relative_to(self.root) or not base.is_dir():
            return []
        return sorted(p for p in base.rglob("*") if p.is_file())

    def list_files(self, directory: str = "") -> str:
        return self._traced("list_files", {"directory": directory}, lambda: self._list_files(directory))

    def _list_files(self, directory: str) -> str:
        files = self._files_under(directory)
        if not files:
            return f"No files found under {directory or 'the package root'!r}."
        lines = []
        for target in files[:MAX_LISTED_FILES]:
            relative = self._relative(target)
            label = f"  [{self.labels[relative]}]" if relative in self.labels else ""
            lines.append(f"{relative}  ({target.stat().st_size} bytes){label}")
        if len(files) > MAX_LISTED_FILES:
            lines.append(f"... {len(files) - MAX_LISTED_FILES} more files not shown; list a subdirectory to see them.")
        return wrap_untrusted("\n".join(lines), source="list_files", directory=directory or ".")

    def read_file(self, path: str, start_line: int = 1, end_line: int = 0) -> str:
        arguments = {"path": path, "start_line": start_line, "end_line": end_line}
        return self._traced("read_file", arguments, lambda: self._read_file(path, start_line, end_line))

    def _read_file(self, path: str, start_line: int, end_line: int) -> str:
        target = self.resolve(path)
        if target is None:
            return f"File not found in the package: {path!r}. Use list_files to see valid paths."
        data = target.read_bytes()
        if b"\x00" in data[:BINARY_SNIFF_BYTES]:
            return f"{path} is a binary file and can't be shown as text."

        relative = self._relative(target)
        if relative not in self.files_read:
            self.files_read.append(relative)
        lines = data.decode("utf-8", "replace").split("\n")
        start = max(1, start_line)
        end = min(len(lines), end_line if end_line >= start else start + MAX_LINES_PER_READ - 1, start + MAX_LINES_PER_READ - 1)
        if start > len(lines):
            return f"{relative} has only {len(lines)} lines."

        numbered = []
        for number in range(start, end + 1):
            line = lines[number - 1]
            if len(line) > MAX_LINE_CHARS:
                line = f"{line[:MAX_LINE_CHARS]} ...[line is {len(line)} chars; use search to find specific content]"
            numbered.append(f"{number:>6}| {line}")
        return wrap_untrusted("\n".join(numbered), source="read_file", path=relative, lines=f"{start}-{end}", total_lines=len(lines))

    def search(self, pattern: str, directory: str = "") -> str:
        return self._traced("search", {"pattern": pattern[:200], "directory": directory}, lambda: self._search(pattern, directory))

    def _search(self, pattern: str, directory: str) -> str:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error:
            regex = re.compile(re.escape(pattern), re.IGNORECASE)

        results = []
        for target in self._files_under(directory):
            if target.stat().st_size > MAX_SEARCH_FILE_BYTES:
                continue
            data = target.read_bytes()
            if b"\x00" in data[:BINARY_SNIFF_BYTES]:
                continue
            for number, line in enumerate(data.decode("utf-8", "replace").split("\n"), 1):
                match = regex.search(line)
                if not match:
                    continue
                start = max(0, match.start() - SEARCH_WINDOW_CHARS // 2)
                results.append(f"{self._relative(target)}:{number}: {line[start : start + SEARCH_WINDOW_CHARS].strip()}")
                if len(results) >= MAX_SEARCH_RESULTS:
                    break
            if len(results) >= MAX_SEARCH_RESULTS:
                results.append(f"... stopped at {MAX_SEARCH_RESULTS} results; narrow the pattern or directory.")
                break
        if not results:
            return f"No matches for {pattern!r}."
        return wrap_untrusted("\n".join(results), source="search", pattern=pattern.replace('"', "'"))

"""Strands tool wrappers around one PackageWorkspace. Read-only: no shell, no network, no code execution."""

from strands import tool

from pkgguard_analyzer.ai.workspace import MAX_LINES_PER_READ, PackageWorkspace


def build_tools(workspace: PackageWorkspace) -> list:
    @tool
    def list_files(directory: str = "") -> str:
        """List files in the package with sizes, marking files that run at install time or on import.

        Args:
            directory: Folder inside the package to list, e.g. "lib". Leave empty for the whole package.
        """
        return workspace.list_files(directory)

    @tool
    def read_file(path: str, start_line: int = 1, end_line: int = 0) -> str:
        """Read lines of a package file, with line numbers. Returns at most 300 lines per call.

        Args:
            path: File path inside the package, e.g. "install.js" or "lib/index.js".
            start_line: First line to read (1-based).
            end_line: Last line to read. Use 0 to read up to 300 lines from start_line.
        """
        return workspace.read_file(path, start_line, end_line)

    @tool
    def search(pattern: str, directory: str = "") -> str:
        """Search package files for a regular expression (case-insensitive). Returns file:line and nearby text.

        Args:
            pattern: Regular expression or plain text, e.g. "child_process" or "https?://".
            directory: Folder inside the package to search. Leave empty to search everything.
        """
        return workspace.search(pattern, directory)

    return [list_files, read_file, search]


__all__ = ["MAX_LINES_PER_READ", "build_tools"]

"""Safe extraction of untrusted npm tarballs. Never trusts paths, links or sizes."""

import io
import shutil
import tarfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

MAX_FILES = 20_000
MAX_UNPACKED_BYTES = 200 * 1024 * 1024


class ArchiveTooLarge(Exception):
    pass


@dataclass
class SkippedEntry:
    path: str
    reason: str  # "path_traversal" | "link" | "special_file"


@dataclass
class ExtractResult:
    file_count: int = 0
    unpacked_bytes: int = 0
    skipped: list[SkippedEntry] = field(default_factory=list)


def safe_extract(
    tarball: bytes,
    dest: Path,
    max_files: int = MAX_FILES,
    max_unpacked_bytes: int = MAX_UNPACKED_BYTES,
) -> ExtractResult:
    """Unpack into dest, stripping the top-level folder (usually "package/"). Links and escaping paths are skipped."""
    result = ExtractResult()
    dest.mkdir(parents=True, exist_ok=True)
    dest = dest.resolve()

    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        for member in tar:
            parts = PurePosixPath(member.name).parts
            if member.name.startswith("/") or ".." in parts:
                result.skipped.append(SkippedEntry(member.name, "path_traversal"))
                continue
            if member.issym() or member.islnk():
                result.skipped.append(SkippedEntry(member.name, "link"))
                continue
            if member.isdir():
                continue
            if not member.isfile():
                result.skipped.append(SkippedEntry(member.name, "special_file"))
                continue

            result.file_count += 1
            result.unpacked_bytes += member.size
            if result.file_count > max_files:
                raise ArchiveTooLarge(f"package has more than {max_files} files")
            if result.unpacked_bytes > max_unpacked_bytes:
                raise ArchiveTooLarge(f"package is larger than {max_unpacked_bytes // (1024 * 1024)} MB unpacked")

            relative = PurePosixPath(*parts[1:]) if len(parts) > 1 else PurePosixPath(*parts)
            target = (dest / relative).resolve()
            if not target.is_relative_to(dest):
                result.skipped.append(SkippedEntry(member.name, "path_traversal"))
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                continue
            with source, target.open("wb") as out:
                shutil.copyfileobj(source, out)

    return result

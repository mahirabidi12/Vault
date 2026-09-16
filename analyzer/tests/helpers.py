import io
import json
import tarfile


def make_tgz(entries: dict[str, bytes | str | None], links: dict[str, str] | None = None) -> bytes:
    """Build a .tgz in memory. entries: path -> content (None = directory); links: path -> symlink target."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        for path, content in entries.items():
            info = tarfile.TarInfo(path)
            if content is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
                continue
            data = content.encode() if isinstance(content, str) else content
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        for path, target in (links or {}).items():
            info = tarfile.TarInfo(path)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            tar.addfile(info)
    return buffer.getvalue()


def make_packument(
    name: str = "demo-pkg",
    version: str = "1.0.0",
    *,
    scripts: dict | None = None,
    published: str = "2025-01-01T00:00:00.000Z",
    publisher: str = "alice",
    repository: str | None = "git+https://github.com/example/demo-pkg.git",
    previous: dict | None = None,
    tarball: str = "https://registry.npmjs.org/demo-pkg/-/demo-pkg-1.0.0.tgz",
    integrity: str | None = None,
    trusted: bool = False,
) -> dict:
    manifest = {
        "name": name,
        "version": version,
        "scripts": scripts or {},
        "_npmUser": {"name": publisher, **({"trustedPublisher": {"id": "github"}} if trusted else {})},
        "maintainers": [{"name": publisher}],
        "dist": {"tarball": tarball, "integrity": integrity},
    }
    if repository:
        manifest["repository"] = {"type": "git", "url": repository}
    packument = {
        "name": name,
        "dist-tags": {"latest": version},
        "versions": {version: manifest},
        "time": {version: published},
    }
    if previous:
        previous_user = {"name": previous.get("publisher", previous["maintainers"][0])}
        if previous.get("trusted"):
            previous_user["trustedPublisher"] = {"id": "github"}
        packument["versions"][previous["version"]] = {
            "name": name,
            "version": previous["version"],
            "maintainers": [{"name": m} for m in previous["maintainers"]],
            "_npmUser": previous_user,
        }
        packument["time"][previous["version"]] = previous["published"]
    return packument


def manifest_json(name: str = "demo-pkg", version: str = "1.0.0", scripts: dict | None = None) -> str:
    return json.dumps({"name": name, "version": version, "scripts": scripts or {}})

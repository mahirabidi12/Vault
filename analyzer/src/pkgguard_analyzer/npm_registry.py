"""npm registry access: package metadata, tarball download, integrity check."""

import base64
import hashlib
from urllib.parse import quote

import httpx

REGISTRY_URL = "https://registry.npmjs.org"
# Much smaller registry response: dist-tags and versions only (no readme, times or maintainers).
ABBREVIATED_METADATA = "application/vnd.npm.install-v1+json"
MAX_TARBALL_BYTES = 50 * 1024 * 1024
SRI_ALGORITHMS = ("sha512", "sha384", "sha256")


class RegistryError(Exception):
    pass


class PackageNotFound(RegistryError):
    pass


class IntegrityError(RegistryError):
    pass


class TarballTooLarge(RegistryError):
    pass


def packument_url(name: str) -> str:
    # Scoped names keep "@" but encode "/": @babel/core -> @babel%2Fcore
    return f"{REGISTRY_URL}/{quote(name, safe='@')}"


def fetch_packument(client: httpx.Client, name: str) -> dict:
    response = client.get(packument_url(name))
    if response.status_code == 404:
        raise PackageNotFound(f"package {name!r} not found on npm")
    response.raise_for_status()
    return response.json()


def fetch_abbreviated_packument(client: httpx.Client, name: str) -> dict:
    """Fast lookup used by the API to resolve versions before deciding whether to scan."""
    response = client.get(packument_url(name), headers={"Accept": ABBREVIATED_METADATA})
    if response.status_code == 404:
        raise PackageNotFound(f"package {name!r} not found on npm")
    response.raise_for_status()
    return response.json()


def resolve_version(packument: dict, requested: str | None) -> str:
    """Turn a dist-tag (default "latest") or exact version into an exact published version."""
    tag = requested or "latest"
    version = packument.get("dist-tags", {}).get(tag, requested)
    if version not in packument.get("versions", {}):
        raise PackageNotFound(f"version {tag!r} not found for {packument.get('name')!r}")
    return version


def download_tarball(client: httpx.Client, url: str, max_bytes: int = MAX_TARBALL_BYTES) -> bytes:
    chunks: list[bytes] = []
    size = 0
    with client.stream("GET", url) as response:
        response.raise_for_status()
        for chunk in response.iter_bytes():
            size += len(chunk)
            if size > max_bytes:
                raise TarballTooLarge(f"tarball is larger than {max_bytes // (1024 * 1024)} MB")
            chunks.append(chunk)
    return b"".join(chunks)


def verify_integrity(data: bytes, integrity: str | None, shasum: str | None) -> None:
    """Check the downloaded bytes match the hash the registry published."""
    checked = False
    for entry in (integrity or "").split():
        algorithm, _, expected = entry.partition("-")
        if algorithm not in SRI_ALGORITHMS:
            continue
        checked = True
        if base64.b64encode(hashlib.new(algorithm, data).digest()).decode() == expected:
            return
    if checked:
        raise IntegrityError("tarball does not match the registry integrity hash")
    if shasum:
        if hashlib.sha1(data).hexdigest() == shasum:
            return
        raise IntegrityError("tarball does not match the registry shasum")
    raise IntegrityError("registry provided no usable integrity hash")

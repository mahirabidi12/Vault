import base64
import hashlib

import pytest

from pkgguard_analyzer.npm_registry import (
    IntegrityError,
    PackageNotFound,
    packument_url,
    resolve_version,
    verify_integrity,
)

DATA = b"tarball bytes"
SHA512 = "sha512-" + base64.b64encode(hashlib.sha512(DATA).digest()).decode()


def test_packument_url_encodes_scoped_names():
    assert packument_url("express") == "https://registry.npmjs.org/express"
    assert packument_url("@babel/core") == "https://registry.npmjs.org/@babel%2Fcore"


def test_resolve_version_defaults_to_latest_tag():
    packument = {"name": "x", "dist-tags": {"latest": "2.0.0", "beta": "3.0.0-beta.1"}, "versions": {"2.0.0": {}, "3.0.0-beta.1": {}}}
    assert resolve_version(packument, None) == "2.0.0"
    assert resolve_version(packument, "beta") == "3.0.0-beta.1"
    assert resolve_version(packument, "2.0.0") == "2.0.0"


def test_resolve_version_rejects_unknown_version():
    with pytest.raises(PackageNotFound):
        resolve_version({"name": "x", "dist-tags": {}, "versions": {"1.0.0": {}}}, "9.9.9")


def test_integrity_match_passes():
    verify_integrity(DATA, SHA512, None)


def test_integrity_mismatch_raises():
    with pytest.raises(IntegrityError):
        verify_integrity(b"tampered", SHA512, None)


def test_shasum_fallback():
    verify_integrity(DATA, None, hashlib.sha1(DATA).hexdigest())
    with pytest.raises(IntegrityError):
        verify_integrity(b"tampered", None, hashlib.sha1(DATA).hexdigest())


def test_missing_hash_raises():
    with pytest.raises(IntegrityError, match="no usable"):
        verify_integrity(DATA, None, None)

"""AWS-side handling of malware samples for the evaluation, so a sample is never downloaded to a laptop.

Two actions, invoked directly on the scan Lambda (not through the public API):
  fetch_samples   download encrypted sample zips (Datadog's malicious-software-packages-dataset, password
                  "infected"), repack each as an npm-style tarball, store in S3 under malware-samples/
  analyze_sample  run the normal pipeline (static + AI + sandbox) on one stored tarball, save the result to
                  S3 under pilot/<run>/, and return only a short summary

Threat intelligence is mocked to "not found" here on purpose: the point is to measure our own layers,
not to look the answer up. Verdicts are never written to the production verdict table."""

import gzip
import io
import json
import logging
import tarfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx

from pkgguard_analyzer.analyze import analyze
from pkgguard_analyzer.schema import RanOn

log = logging.getLogger()
ZIP_PASSWORD = b"infected"
MAX_ZIP_BYTES = 30 * 1024 * 1024
MAX_UNPACKED_BYTES = 120 * 1024 * 1024
MAX_FILES = 6000
SAMPLE_PREFIX = "malware-samples"
ALLOWED_URL_PREFIX = "https://raw.githubusercontent.com/DataDog/malicious-software-packages-dataset/"


def sample_key(dir_name: str, version: str) -> str:
    return f"{SAMPLE_PREFIX}/{dir_name}/{version}.tgz"


def repack(zip_bytes: bytes) -> tuple[bytes, dict]:
    """Encrypted sample zip -> (npm-style tarball with a top-level `package/` folder, its package.json).
    Nothing is executed; files are only copied. Unsafe paths are dropped."""
    zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    entries = [i for i in zf.infolist() if not i.is_dir()]
    manifests = [i for i in entries if i.filename.endswith("package.json") and "node_modules/" not in i.filename]
    if not manifests:
        raise ValueError("no package.json in the sample")
    top = min(manifests, key=lambda i: i.filename.count("/"))
    prefix = top.filename[: -len("package.json")]
    total = 0
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w:gz") as tar:
        for info in entries[:MAX_FILES]:
            if not info.filename.startswith(prefix):
                continue
            rel = info.filename[len(prefix):]
            if not rel or rel.startswith("/") or ".." in Path(rel).parts:
                continue
            data = zf.read(info, pwd=ZIP_PASSWORD)
            total += len(data)
            if total > MAX_UNPACKED_BYTES:
                raise ValueError("sample unpacks to more than the size limit")
            member = tarfile.TarInfo(f"package/{rel}")
            member.size, member.mode = len(data), 0o644
            tar.addfile(member, io.BytesIO(data))
    manifest = json.loads(zf.read(top, pwd=ZIP_PASSWORD).decode("utf-8", "replace"))
    return out.getvalue(), manifest if isinstance(manifest, dict) else {}


def fetch_samples(event: dict, s3: Any, bucket: str, http: httpx.Client | None = None) -> dict:
    client = http or httpx.Client(timeout=60, follow_redirects=True)
    results = []
    for sample in event["samples"]:
        result = {"name": sample["name"], "version": sample["version"], "dirName": sample["dirName"], "ok": False}
        try:
            if not sample["url"].startswith(ALLOWED_URL_PREFIX):
                raise ValueError("sample URL is not from the dataset")
            resp = client.get(sample["url"])
            resp.raise_for_status()
            if len(resp.content) > MAX_ZIP_BYTES:
                raise ValueError(f"zip is {len(resp.content)} bytes, over the limit")
            tarball, manifest = repack(resp.content)
            key = sample_key(sample["dirName"], sample["version"])
            s3.put_object(Bucket=bucket, Key=key, Body=tarball, ContentType="application/gzip")
            result.update(ok=True, s3Key=key, bytes=len(tarball), declaredName=manifest.get("name"), declaredVersion=manifest.get("version"))
        except Exception as error:
            result["error"] = f"{type(error).__name__}: {error}"[:200]
        results.append(result)
    return {"results": results}


def _mock_registry(name: str, version: str, manifest: dict, tarball: bytes) -> httpx.Client:
    from pkgguard_analyzer.eval import _build_packument, _mock_transport

    url = f"https://registry.npmjs.org/{name}/-/{name.split('/')[-1]}-{version}.tgz"
    packument = _build_packument({**manifest, "name": name, "version": version}, tarball, url, datetime.now(UTC) - timedelta(days=200))
    return httpx.Client(transport=_mock_transport(packument, tarball, url))


def analyze_sample(event: dict, services: Any, work_root: Path) -> dict:
    from pkgguard_analyzer.sandbox.pilot import summarize

    sample = event["sample"]
    name, version, label = sample["name"], sample["version"], sample.get("label", "malicious")
    body = services.s3.get_object(Bucket=services.bucket, Key=sample["s3Key"])["Body"].read()
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as tar:
        manifest_file = tar.extractfile("package/package.json")
        manifest = json.loads(manifest_file.read().decode("utf-8", "replace")) if manifest_file else {}
    scan_id = f"sample-{event.get('run', 'run')}-{name.replace('/', '_').replace('@', '')}"[:100]
    client = _mock_registry(name, version, manifest if isinstance(manifest, dict) else {}, body)
    try:
        result = analyze(
            name, version, out_dir=work_root / scan_id, ran_on=RanOn.CLOUD, client=client, reviewer=services.reviewer, ai_mode=services.ai_mode,
            scan_id=scan_id, sandbox_runner=services.sandbox.runner_for(scan_id, name, version) if services.sandbox else None,
        )  # fmt: skip
    finally:
        client.close()
    summary = summarize(name, label, result.record, result.report, 0.0)
    key = f"pilot/{event.get('run', 'run')}/{name.replace('/', '__')}.json"
    services.s3.put_object(
        Bucket=services.bucket, Key=key, ContentType="application/json",
        Body=json.dumps({"summary": summary, "record": result.record.model_dump(mode="json", by_alias=True), "report": result.report.model_dump(mode="json", by_alias=True) if result.report else None}).encode(),
    )  # fmt: skip
    return {"summary": summary, "resultKey": key}

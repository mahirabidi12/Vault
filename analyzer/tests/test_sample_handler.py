"""Sample fetching and analysis, with a fake HTTP server and moto S3. Uses harmless zips only."""

import io
import json
import tarfile
import zipfile

import boto3
import httpx
import pytest
from moto import mock_aws

from pkgguard_analyzer.cloud.sample_handler import ALLOWED_URL_PREFIX, analyze_sample, fetch_samples, repack, sample_key
from pkgguard_analyzer.cloud.scan_handler import ScanServices

BUCKET = "reports"


def make_zip(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, text in files.items():
            zf.writestr(name, text)
    return buf.getvalue()


def names(tarball: bytes) -> list[str]:
    return tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz").getnames()


def test_repack_strips_the_wrapper_folder_and_drops_unsafe_paths() -> None:
    zipped = make_zip({"2025-01-01-demo-v1.0.0/package.json": '{"name":"demo","version":"1.0.0"}', "2025-01-01-demo-v1.0.0/lib/a.js": "x", "2025-01-01-demo-v1.0.0/../evil.js": "y", "other/readme.md": "z"})
    tarball, manifest = repack(zipped)
    assert manifest["name"] == "demo"
    assert sorted(names(tarball)) == ["package/lib/a.js", "package/package.json"]


def test_repack_handles_a_nested_package_folder() -> None:
    tarball, _ = repack(make_zip({"wrapper/package/package.json": '{"name":"a","version":"1.0.0"}', "wrapper/package/index.js": "1"}))
    assert sorted(names(tarball)) == ["package/index.js", "package/package.json"]


def test_repack_rejects_a_zip_without_a_manifest() -> None:
    with pytest.raises(ValueError, match="no package.json"):
        repack(make_zip({"a/readme.md": "x"}))


@pytest.fixture
def s3():
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket=BUCKET)
        yield client


def test_fetch_stores_the_tarball_and_reports_failures_per_sample(s3) -> None:
    good = make_zip({"d/package.json": '{"name":"demo","version":"1.0.0"}', "d/index.js": "1"})

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=good) if request.url.path.endswith("good.zip") else httpx.Response(404)

    http = httpx.Client(transport=httpx.MockTransport(handler))
    event = {"samples": [
        {"name": "demo", "version": "1.0.0", "dirName": "demo", "url": ALLOWED_URL_PREFIX + "main/good.zip"},
        {"name": "gone", "version": "1.0.0", "dirName": "gone", "url": ALLOWED_URL_PREFIX + "main/missing.zip"},
        {"name": "evil", "version": "1.0.0", "dirName": "evil", "url": "https://example.com/x.zip"},
    ]}  # fmt: skip
    out = fetch_samples(event, s3, BUCKET, http)["results"]
    assert [r["ok"] for r in out] == [True, False, False]
    assert "not from the dataset" in out[2]["error"]
    assert sorted(names(s3.get_object(Bucket=BUCKET, Key=sample_key("demo", "1.0.0"))["Body"].read())) == ["package/index.js", "package/package.json"]


def test_analyze_sample_saves_the_result_and_returns_only_a_summary(s3, tmp_path) -> None:
    tarball, _ = repack(make_zip({"d/package.json": json.dumps({"name": "demo-sample", "version": "1.0.0", "scripts": {"postinstall": "node p.js"}}), "d/p.js": "require('https').get('https://x.example.invalid/')"}))
    s3.put_object(Bucket=BUCKET, Key=sample_key("demo-sample", "1.0.0"), Body=tarball)
    services = ScanServices(store=None, s3=s3, bucket=BUCKET)
    out = analyze_sample({"run": "t1", "sample": {"name": "demo-sample", "version": "1.0.0", "label": "malicious", "s3Key": sample_key("demo-sample", "1.0.0")}}, services, tmp_path)
    assert out["summary"]["status"] == "COMPLETE" and out["summary"]["label"] == "malicious"
    assert out["resultKey"] == "pilot/t1/demo-sample.json"
    saved = json.loads(s3.get_object(Bucket=BUCKET, Key=out["resultKey"])["Body"].read())
    assert saved["record"]["package"]["name"] == "demo-sample" and saved["report"]["findings"]

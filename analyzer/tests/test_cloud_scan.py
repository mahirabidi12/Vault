import json

from cloud_helpers import BUCKET, NOW, record
from helpers import make_packument, make_tgz, manifest_json
from test_analyze import TARBALL_URL, mock_client, sri

from pkgguard_analyzer.cloud import failure_handler, scan_handler
from pkgguard_analyzer.cloud.scan_handler import ScanServices
from pkgguard_analyzer.schema import ScanStatus

SCAN_ID = "01JSCANSCANSCANSCANSCANSCA"


def start_pending(cloud, name="demo-pkg", version="1.0.0"):
    cloud.store.claim_scan(record(name=name, version=version, status=ScanStatus.PENDING, scan_id=SCAN_ID), NOW)


def test_scan_saves_verdict_and_report(cloud, tmp_path, monkeypatch):
    monkeypatch.setattr(scan_handler, "WORK_ROOT", tmp_path)
    start_pending(cloud)
    tarball = make_tgz({"package/package.json": manifest_json(), "package/index.js": "module.exports = 1"})
    services = ScanServices(cloud.store, cloud.s3, BUCKET, http=mock_client(tarball, sri(tarball)))

    result = scan_handler.handler({"name": "demo-pkg", "version": "1.0.0", "scanId": SCAN_ID}, None, services)

    assert result == {"scanId": SCAN_ID, "status": "COMPLETE", "verdict": "SAFE"}
    saved = cloud.store.get("demo-pkg", "1.0.0")
    assert (saved.status, saved.ran_on, saved.scan_id) == (ScanStatus.COMPLETE, "cloud", SCAN_ID)
    report = json.loads(cloud.s3.get_object(Bucket=BUCKET, Key=saved.report_s3_key)["Body"].read())
    assert report["package"]["name"] == "demo-pkg" and report["codeScan"]["filesScanned"] == 1
    assert cloud.store.stats()["safe"] == 1
    assert not (tmp_path / SCAN_ID).exists()


def test_superseded_scan_does_nothing(cloud, tmp_path, monkeypatch):
    monkeypatch.setattr(scan_handler, "WORK_ROOT", tmp_path)
    start_pending(cloud)
    services = ScanServices(cloud.store, cloud.s3, BUCKET)
    result = scan_handler.handler({"name": "demo-pkg", "version": "1.0.0", "scanId": "01JOTHEROTHEROTHEROTHEROTH"}, None, services)
    assert result["status"] == "SUPERSEDED"
    assert cloud.store.get("demo-pkg", "1.0.0").status == ScanStatus.PENDING


def test_failure_handler_marks_failed(cloud):
    start_pending(cloud)
    cause = json.dumps({"errorMessage": "version '1.0.0' not found for 'demo-pkg'", "errorType": "PackageNotFound"})
    event = {"name": "demo-pkg", "version": "1.0.0", "scanId": SCAN_ID, "error": {"Error": "PackageNotFound", "Cause": cause}}
    assert failure_handler.handler(event, None, cloud.store)["saved"] is True
    failed = cloud.store.get("demo-pkg", "1.0.0")
    assert failed.status == ScanStatus.FAILED
    assert failed.failure_reason == "PackageNotFound: version '1.0.0' not found for 'demo-pkg'"


def test_failure_reason_for_timeouts():
    assert failure_handler.failure_reason({"Error": "States.Timeout", "Cause": ""}) == "States.Timeout"


def test_load_ai_reads_key_from_secrets_manager(cloud, monkeypatch):
    import boto3

    secrets = boto3.client("secretsmanager")
    secrets.create_secret(Name="pkgguard/openai-api-key", SecretString="sk-test")
    for key, value in {"AI_MODE": "always", "OPENAI_MODEL": "gpt-5-mini", "OPENAI_SECRET_NAME": "pkgguard/openai-api-key"}.items():
        monkeypatch.setenv(key, value)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    reviewer, mode = scan_handler.load_ai(secrets)
    assert reviewer is not None and reviewer.model_id == "gpt-5-mini" and mode == "always"


def test_load_ai_without_secret_disables_ai(cloud, monkeypatch):
    import boto3

    monkeypatch.setenv("OPENAI_SECRET_NAME", "missing-secret")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-5-mini")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert scan_handler.load_ai(boto3.client("secretsmanager")) == (None, "off")

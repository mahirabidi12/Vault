import json

from cloud_helpers import BUCKET, NOW, http_event, record

from pkgguard_analyzer.cloud.api import handler
from pkgguard_analyzer.schema import ScanStatus

EXPRESS = {"name": "express", "dist-tags": {"latest": "4.21.0"}, "versions": {"4.18.2": {}, "4.21.0": {}}}


def call(services, *args, **kwargs):
    response = handler(http_event(*args, **kwargs), None, services)
    return response["statusCode"], json.loads(response["body"])


def seed_complete(cloud, name="express", version="4.18.2", **extra):
    done = record(name=name, version=version, scan_id=f"01J{name.upper():Z<23}"[:26], **extra)
    cloud.store.claim_scan(done.model_copy(update={"status": ScanStatus.PENDING}), NOW)
    cloud.store.save_result(done)
    return done


def test_cached_package_answers_without_scanning(cloud):
    seed_complete(cloud)
    status, body = call(cloud.services(), "GET", "/v1/package", {"name": "express", "version": "4.18.2"})
    assert status == 200 and body["verdict"] == "SAFE"
    assert cloud.executions() == []


def test_unknown_package_starts_one_scan(cloud):
    services = cloud.services({"express": EXPRESS})
    status, body = call(services, "GET", "/v1/package", {"name": "express", "version": "4.18.2"})
    assert status == 202 and body["status"] == "PENDING"
    assert cloud.execution_inputs() == [{"name": "express", "version": "4.18.2", "scanId": body["scanId"]}]

    status, again = call(services, "GET", "/v1/package", {"name": "express", "version": "4.18.2"}, ip="5.6.7.8")
    assert status == 202 and again["scanId"] == body["scanId"]
    assert len(cloud.executions()) == 1


def test_missing_version_resolves_latest(cloud):
    status, body = call(cloud.services({"express": EXPRESS}), "GET", "/v1/package", {"name": "express"})
    assert status == 202 and body["package"]["version"] == "4.21.0"


def test_scoped_packages(cloud):
    babel = {"name": "@babel/core", "dist-tags": {"latest": "8.0.5"}, "versions": {"8.0.5": {}}}
    status, body = call(cloud.services({"@babel/core": babel}), "GET", "/v1/package", {"name": "@babel/core"})
    assert status == 202 and body["package"]["name"] == "@babel/core"


def test_bad_requests(cloud):
    services = cloud.services({"express": EXPRESS})
    assert call(services, "GET", "/v1/package", {"name": "../evil"})[0] == 400
    assert call(services, "GET", "/v1/package", {"name": "requests", "ecosystem": "pypi"})[0] == 400
    assert call(services, "GET", "/v1/package", {"name": "does-not-exist"})[0] == 404
    assert call(services, "GET", "/v1/package", {"name": "express", "version": "9.9.9"})[0] == 404
    assert call(services, "GET", "/v1/nope")[0] == 404
    assert cloud.executions() == []


def test_scan_limits_return_429(cloud):
    services = cloud.services({"express": EXPRESS, "lodash": {"name": "lodash", "dist-tags": {"latest": "4.17.21"}, "versions": {"4.17.21": {}}}}, max_new_scans_per_client_per_day=1)
    assert call(services, "GET", "/v1/package", {"name": "express"})[0] == 202
    status, body = call(services, "GET", "/v1/package", {"name": "lodash"})
    assert status == 429 and "limit" in body["error"]


def test_batch_check(cloud):
    seed_complete(cloud)
    packages = [
        {"ecosystem": "npm", "name": "express", "version": "4.18.2"},
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
        {"ecosystem": "npm", "name": "lodash", "version": "4.17.21"},
        {"ecosystem": "npm", "name": "axios", "version": "^1.0.0"},
    ]
    status, body = call(cloud.services(), "POST", "/v1/check", body={"packages": packages})
    assert status == 200
    assert [(r["package"]["name"], r["status"]) for r in body["results"]] == [("express", "COMPLETE"), ("lodash", "PENDING")]
    assert len(body["errors"]) == 1 and body["errors"][0]["package"]["name"] == "axios"
    assert len(cloud.executions()) == 1


def test_batch_check_rejects_bad_body(cloud):
    assert call(cloud.services(), "POST", "/v1/check", body={"nope": []})[0] == 400


def test_report_and_scan_lookup(cloud):
    done = seed_complete(cloud, report_s3_key="reports/npm/express/4.18.2/0.1.0.json")
    cloud.s3.put_object(Bucket=BUCKET, Key=done.report_s3_key, Body=b'{"findings": []}')
    services = cloud.services()
    assert call(services, "GET", "/v1/report", {"name": "express", "version": "4.18.2"}) == (200, {"findings": []})
    assert call(services, "GET", "/v1/report", {"name": "lodash", "version": "4.17.21"})[0] == 404
    assert call(services, "GET", "/v1/report", {"name": "express"})[0] == 400
    status, body = call(services, "GET", f"/v1/scans/{done.scan_id}")
    assert status == 200 and body["scanId"] == done.scan_id


def test_no_api_key_configured_allows_any_request(cloud):
    seed_complete(cloud)
    status, _ = call(cloud.services(api_key=None), "GET", "/v1/package", {"name": "express", "version": "4.18.2"})
    assert status == 200


def test_wrong_or_missing_api_key_is_rejected(cloud):
    seed_complete(cloud)
    services = cloud.services(api_key="the-real-key")
    status, body = call(services, "GET", "/v1/package", {"name": "express", "version": "4.18.2"})
    assert status == 401 and "API key" in body["error"]

    status, _ = call(services, "GET", "/v1/package", {"name": "express", "version": "4.18.2"}, headers={"x-api-key": "wrong"})
    assert status == 401


def test_correct_api_key_is_accepted(cloud):
    seed_complete(cloud)
    services = cloud.services(api_key="the-real-key")
    status, _ = call(services, "GET", "/v1/package", {"name": "express", "version": "4.18.2"}, headers={"x-api-key": "the-real-key"})
    assert status == 200


def test_feed_stats_and_versions(cloud):
    seed_complete(cloud, name="bad-pkg", verdict="MALICIOUS")
    seed_complete(cloud)
    cloud.store.record_completed(record(verdict="MALICIOUS"))
    services = cloud.services()
    assert [i["package"]["name"] for i in call(services, "GET", "/v1/feed")[1]["items"]] == ["bad-pkg"]
    assert call(services, "GET", "/v1/stats")[1]["malicious"] == 1
    assert [i["package"]["version"] for i in call(services, "GET", "/v1/package/versions", {"name": "express"})[1]["items"]] == ["4.18.2"]

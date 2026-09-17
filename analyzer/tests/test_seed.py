import json

from cloud_helpers import BUCKET, NOW, record

from pkgguard_analyzer import seed
from pkgguard_analyzer.schema import PackageRef, Report, ScanStatus


def write_result(out, rec, with_report=True):
    scan_dir = out / rec.package.name / rec.package.version
    scan_dir.mkdir(parents=True)
    (scan_dir / "record.json").write_text(rec.model_dump_json(by_alias=True))
    if with_report:
        report = Report(package=rec.package, analyzer_version="0.1.0", generated_at=NOW)
        (scan_dir / "report.json").write_text(report.model_dump_json(by_alias=True))


def test_default_list_has_50_valid_names():
    names = seed.default_packages()
    assert len(names) == 50 and len(set(names)) == 50
    for name in names:
        PackageRef(ecosystem="npm", name=name, version="1.0.0")


def test_saved_results_reads_scoped_packages(tmp_path):
    write_result(tmp_path, record(name="@babel/core", version="8.0.5"))
    write_result(tmp_path, record(name="express"), with_report=False)
    saved = seed.saved_results(tmp_path)
    assert sorted(r.package.name for r, _ in saved) == ["@babel/core", "express"]
    assert {r.package.name: rep is not None for r, rep in saved} == {"@babel/core": True, "express": False}


def test_upload_writes_records_and_reports(cloud, tmp_path):
    write_result(tmp_path, record(name="express", ranOn="local"))
    write_result(tmp_path, record(name="broken", status=ScanStatus.FAILED))
    uploaded, skipped = seed.upload_results(seed.saved_results(tmp_path), cloud.store, cloud.s3, BUCKET, force=False)
    assert (uploaded, skipped) == (1, 1)

    stored = cloud.store.get("express", "4.18.2")
    assert stored.ran_on == "local" and stored.report_s3_key == "reports/npm/express/4.18.2/0.1.0.json"
    body = json.loads(cloud.s3.get_object(Bucket=BUCKET, Key=stored.report_s3_key)["Body"].read())
    assert body["package"]["name"] == "express"
    assert cloud.store.stats()["scansCompleted"] == 1


def test_upload_keeps_existing_cloud_results_unless_forced(cloud, tmp_path):
    cloud_record = record(name="express", scan_id="01JCLOUDCLOUDCLOUDCLOUDCLO")
    cloud.store.put_seeded(cloud_record)
    write_result(tmp_path, record(name="express", scan_id="01JLOCALLOCALLOCALLOCALLOC"))
    assert seed.upload_results(seed.saved_results(tmp_path), cloud.store, cloud.s3, BUCKET, force=False) == (0, 1)
    assert cloud.store.get("express", "4.18.2").scan_id == cloud_record.scan_id
    assert seed.upload_results(seed.saved_results(tmp_path), cloud.store, cloud.s3, BUCKET, force=True) == (1, 0)
    assert cloud.store.get("express", "4.18.2").scan_id == "01JLOCALLOCALLOCALLOCALLOC"

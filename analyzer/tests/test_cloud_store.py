from datetime import timedelta

from cloud_helpers import NOW, record

from pkgguard_analyzer.schema import ScanStatus


def test_claim_scan_only_one_winner(cloud):
    first = record(status=ScanStatus.PENDING, scan_id="01JAAAAAAAAAAAAAAAAAAAAAAA")
    second = record(status=ScanStatus.PENDING, scan_id="01JBBBBBBBBBBBBBBBBBBBBBBB")
    assert cloud.store.claim_scan(first, NOW - timedelta(minutes=15)) == (True, first)
    claimed, current = cloud.store.claim_scan(second, NOW - timedelta(minutes=15))
    assert claimed is False
    assert current.scan_id == first.scan_id


def test_stale_pending_and_old_failures_can_be_reclaimed(cloud):
    old = NOW - timedelta(hours=1)
    cloud.store.claim_scan(record(status=ScanStatus.PENDING, requested_at=old, scan_id="01JOLDOLDOLDOLDOLDOLDOLDOL"), old)
    fresh = record(status=ScanStatus.PENDING, scan_id="01JNEWNEWNEWNEWNEWNEWNEWNE")
    assert cloud.store.claim_scan(fresh, NOW - timedelta(minutes=15))[0] is True


def test_completed_record_is_never_reclaimed(cloud):
    old = NOW - timedelta(days=30)
    cloud.store.claim_scan(record(status=ScanStatus.PENDING, requested_at=old, scan_id="01JDONEDONEDONEDONEDONEDON"), old)
    done = record(requested_at=old, scan_id="01JDONEDONEDONEDONEDONEDON")
    assert cloud.store.save_result(done)
    assert cloud.store.claim_scan(record(status=ScanStatus.PENDING, scan_id="01JXXXXXXXXXXXXXXXXXXXXXXX"), NOW)[0] is False


def test_scan_lifecycle_and_superseded_scans(cloud):
    pending = record(status=ScanStatus.PENDING, scan_id="01JCURRENTCURRENTCURRENTCU")
    cloud.store.claim_scan(pending, NOW)
    assert cloud.store.mark_scanning("express", "4.18.2", "01JWRONGWRONGWRONGWRONGWRO") is None
    scanning = cloud.store.mark_scanning("express", "4.18.2", pending.scan_id)
    assert scanning.status == ScanStatus.SCANNING
    assert cloud.store.save_result(record(scan_id="01JWRONGWRONGWRONGWRONGWRO")) is False
    assert cloud.store.save_result(record(scan_id=pending.scan_id)) is True
    assert cloud.store.get("express", "4.18.2").status == ScanStatus.COMPLETE
    assert cloud.store.by_scan_id(pending.scan_id).scan_id == pending.scan_id


def test_save_failed(cloud):
    pending = record(status=ScanStatus.PENDING, scan_id="01JFAILFAILFAILFAILFAILFAI")
    cloud.store.claim_scan(pending, NOW)
    assert cloud.store.save_failed("express", "4.18.2", pending.scan_id, "PackageNotFound: gone")
    failed = cloud.store.get("express", "4.18.2")
    assert (failed.status, failed.failure_reason) == (ScanStatus.FAILED, "PackageNotFound: gone")


def _complete(cloud, name, verdict, minutes):
    at = NOW + timedelta(minutes=minutes)
    scan_id = f"01J{name.upper():A<23}"[:26]
    cloud.store.claim_scan(record(name=name, status=ScanStatus.PENDING, scan_id=scan_id, requested_at=at), at)
    cloud.store.save_result(record(name=name, verdict=verdict, scan_id=scan_id, requested_at=at, analyzed_at=at))


def test_feed_lists_threats_newest_first(cloud):
    _complete(cloud, "old-bad", "MALICIOUS", 1)
    _complete(cloud, "odd", "SUSPICIOUS", 2)
    _complete(cloud, "fine", "SAFE", 3)
    _complete(cloud, "new-bad", "MALICIOUS", 4)
    assert [r.package.name for r in cloud.store.feed()] == ["new-bad", "odd", "old-bad"]


def test_get_many_handles_more_than_100(cloud):
    for i in range(120):
        cloud.store.claim_scan(record(name=f"pkg-{i}", status=ScanStatus.PENDING, scan_id=f"01J{i:023d}"), NOW)
    found = cloud.store.get_many([(f"pkg-{i}", "4.18.2") for i in range(130)])
    assert len(found) == 120


def test_daily_quotas(cloud):
    for _ in range(2):
        assert cloud.store.consume_scan_quota("ip-a", NOW, per_client=2, per_day=3) is None
    assert "You've reached" in cloud.store.consume_scan_quota("ip-a", NOW, per_client=2, per_day=3)
    assert cloud.store.consume_scan_quota("ip-b", NOW, per_client=2, per_day=3) is None
    assert "PkgGuard has reached" in cloud.store.consume_scan_quota("ip-c", NOW, per_client=2, per_day=3)
    assert cloud.store.consume_scan_quota("ip-a", NOW + timedelta(days=1), per_client=2, per_day=3) is None


def test_stats(cloud):
    cloud.store.record_completed(record(verdict="SAFE"))
    cloud.store.record_completed(record(verdict="MALICIOUS"))
    assert cloud.store.stats() == {"scansCompleted": 2, "safe": 1, "suspicious": 0, "malicious": 1, "skipped": 0}

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from pkgguard_analyzer.schema import Finding, PackageRef, ScanStatus, VerdictRecord

NOW = datetime(2026, 9, 17, tzinfo=UTC)


def base_record(**overrides):
    data = {
        "package": {"ecosystem": "npm", "name": "express", "version": "4.18.2"},
        "status": "PENDING",
        "scanId": "01J0000000000000000000000",
        "requestedAt": NOW,
        "ranOn": "local",
        "analyzerVersion": "0.1.0",
    }
    data.update(overrides)
    return data


def test_pending_record_is_valid():
    record = VerdictRecord.model_validate(base_record())
    assert record.status == ScanStatus.PENDING
    assert record.verdict is None


def test_complete_record_round_trips_as_camel_case_json():
    record = VerdictRecord.model_validate(
        base_record(
            status="COMPLETE",
            verdict="SAFE",
            confidence="HIGH",
            decidedBy="rules",
            summary="No issues found.",
            analyzedAt=NOW,
        )
    )
    dumped = record.model_dump(mode="json", by_alias=True)
    assert dumped["decidedBy"] == "rules"
    assert "decided_by" not in dumped
    assert VerdictRecord.model_validate(dumped) == record


def test_complete_record_requires_verdict_fields():
    with pytest.raises(ValidationError, match="missing"):
        VerdictRecord.model_validate(base_record(status="COMPLETE"))


def test_pending_record_cannot_have_verdict():
    with pytest.raises(ValidationError, match="must not have a verdict"):
        VerdictRecord.model_validate(base_record(verdict="SAFE"))


def test_failed_record_requires_reason():
    with pytest.raises(ValidationError, match="failure_reason"):
        VerdictRecord.model_validate(base_record(status="FAILED"))


def test_naive_datetime_rejected():
    with pytest.raises(ValidationError):
        VerdictRecord.model_validate(base_record(requestedAt=datetime(2026, 9, 17)))


@pytest.mark.parametrize("name", ["express", "@babel/core", "lodash.merge", "socket.io"])
def test_valid_package_names(name):
    assert PackageRef(ecosystem="npm", name=name, version="1.0.0").name == name


@pytest.mark.parametrize("name", ["Express", "@babel", "../evil", "", "has space"])
def test_invalid_package_names(name):
    with pytest.raises(ValidationError):
        PackageRef(ecosystem="npm", name=name, version="1.0.0")


@pytest.mark.parametrize("version", ["1.0.0", "4.18.2", "1.0.0-beta.1", "2.0.0+build.5"])
def test_exact_versions_accepted(version):
    assert PackageRef(ecosystem="npm", name="x", version=version).version == version


@pytest.mark.parametrize("version", ["latest", "^1.2.0", "~1.2.0", "1.x", "1.2", ">=1.0.0"])
def test_ranges_and_tags_rejected(version):
    with pytest.raises(ValidationError, match="exact"):
        PackageRef(ecosystem="npm", name="x", version=version)


def test_finding_line_must_be_positive():
    with pytest.raises(ValidationError):
        Finding(ruleId="r", layer="static", severity="LOW", confidence="LOW", title="t", line=0)

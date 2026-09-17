"""DynamoDB storage for verdicts, stats and daily scan limits.

Each package version is one item: indexed attributes (status, scanId, feed keys) plus the full
VerdictRecord as a JSON string, so the stored shape always matches schema.py.
"""

import time
from datetime import UTC, datetime, timedelta

from boto3.dynamodb.conditions import Key
from botocore.exceptions import ClientError

from pkgguard_analyzer.schema import ScanStatus, Verdict, VerdictRecord

FEED_INDEX = "Feed"
SCAN_ID_INDEX = "ByScanId"
FEED_VERDICTS = (Verdict.MALICIOUS, Verdict.SUSPICIOUS)
BATCH_GET_LIMIT = 100
RETRYABLE_STATUSES = frozenset({ScanStatus.PENDING, ScanStatus.SCANNING, ScanStatus.FAILED})


def package_key(name: str, version: str) -> dict[str, str]:
    return {"PK": f"PKG#npm#{name}", "SK": f"VER#{version}"}


def _epoch(moment: datetime) -> int:
    return int(moment.timestamp())


def _record(item: dict) -> VerdictRecord:
    return VerdictRecord.model_validate_json(item["record"])


def _conditional_failed(error: ClientError) -> bool:
    return error.response["Error"]["Code"] == "ConditionalCheckFailedException"


def needs_rescan(record: VerdictRecord, stale_before: datetime) -> bool:
    """Pending scans that never finished, and failures, get another try once they're old enough."""
    return record.status in RETRYABLE_STATUSES and record.requested_at < stale_before


class VerdictStore:
    def __init__(self, dynamodb, table_name: str):
        self.dynamodb = dynamodb  # boto3 DynamoDB service resource
        self.table = dynamodb.Table(table_name)

    def _item(self, record: VerdictRecord) -> dict:
        item = {
            **package_key(record.package.name, record.package.version),
            "scanId": record.scan_id,
            "status": record.status.value,
            "requestedAtEpoch": _epoch(record.requested_at),
            "record": record.model_dump_json(by_alias=True),
        }
        if record.status == ScanStatus.COMPLETE and record.verdict in FEED_VERDICTS and record.analyzed_at:
            item["GSI1PK"] = f"VERDICT#{record.verdict.value}"
            item["GSI1SK"] = record.analyzed_at.astimezone(UTC).isoformat()
        return item

    def get(self, name: str, version: str) -> VerdictRecord | None:
        item = self.table.get_item(Key=package_key(name, version), ConsistentRead=True).get("Item")
        return _record(item) if item else None

    def get_many(self, packages: list[tuple[str, str]]) -> dict[tuple[str, str], VerdictRecord]:
        found: dict[tuple[str, str], VerdictRecord] = {}
        unique = list(dict.fromkeys(packages))
        for start in range(0, len(unique), BATCH_GET_LIMIT):
            request = {
                self.table.name: {"Keys": [package_key(n, v) for n, v in unique[start : start + BATCH_GET_LIMIT]], "ConsistentRead": True}
            }
            while request:
                response = self.dynamodb.batch_get_item(RequestItems=request)
                for item in response["Responses"].get(self.table.name, []):
                    record = _record(item)
                    found[(record.package.name, record.package.version)] = record
                request = response.get("UnprocessedKeys") or None
                if request:
                    time.sleep(0.2)
        return found

    def by_scan_id(self, scan_id: str) -> VerdictRecord | None:
        items = self.table.query(IndexName=SCAN_ID_INDEX, KeyConditionExpression=Key("scanId").eq(scan_id), Limit=1).get("Items", [])
        return _record(items[0]) if items else None

    def versions(self, name: str, limit: int = 50) -> list[VerdictRecord]:
        items = self.table.query(
            KeyConditionExpression=Key("PK").eq(f"PKG#npm#{name}") & Key("SK").begins_with("VER#"), Limit=limit
        ).get("Items", [])
        return sorted((_record(item) for item in items), key=lambda r: r.requested_at, reverse=True)

    def feed(self, limit: int = 50) -> list[VerdictRecord]:
        records: list[VerdictRecord] = []
        for verdict in FEED_VERDICTS:
            items = self.table.query(
                IndexName=FEED_INDEX,
                KeyConditionExpression=Key("GSI1PK").eq(f"VERDICT#{verdict.value}"),
                ScanIndexForward=False,
                Limit=limit,
            ).get("Items", [])
            records += [_record(item) for item in items]
        return sorted(records, key=lambda r: r.analyzed_at, reverse=True)[:limit]

    def claim_scan(self, pending: VerdictRecord, stale_before: datetime) -> tuple[bool, VerdictRecord | None]:
        """Create the PENDING record unless a usable one exists. Only one caller can win, so each version is scanned once."""
        try:
            self.table.put_item(
                Item=self._item(pending),
                ConditionExpression="attribute_not_exists(PK) OR (#status IN (:pending, :scanning, :failed) AND requestedAtEpoch < :stale)",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":pending": ScanStatus.PENDING.value,
                    ":scanning": ScanStatus.SCANNING.value,
                    ":failed": ScanStatus.FAILED.value,
                    ":stale": _epoch(stale_before),
                },
            )
            return True, pending
        except ClientError as error:
            if not _conditional_failed(error):
                raise
            return False, self.get(pending.package.name, pending.package.version)

    def _replace_if_current(self, record: VerdictRecord, allowed: tuple[ScanStatus, ...]) -> bool:
        """Write only if this record's scan is still the current one, so an old scan can't overwrite a newer one."""
        values = {f":s{i}": status.value for i, status in enumerate(allowed)}
        try:
            self.table.put_item(
                Item=self._item(record),
                ConditionExpression=f"scanId = :scan AND #status IN ({', '.join(values)})",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":scan": record.scan_id, **values},
            )
            return True
        except ClientError as error:
            if not _conditional_failed(error):
                raise
            return False

    def mark_scanning(self, name: str, version: str, scan_id: str) -> VerdictRecord | None:
        current = self.get(name, version)
        if current is None or current.scan_id != scan_id or current.status != ScanStatus.PENDING:
            return None
        scanning = current.model_copy(update={"status": ScanStatus.SCANNING})
        return scanning if self._replace_if_current(scanning, (ScanStatus.PENDING,)) else None

    def save_result(self, record: VerdictRecord) -> bool:
        return self._replace_if_current(record, (ScanStatus.PENDING, ScanStatus.SCANNING))

    def save_failed(self, name: str, version: str, scan_id: str, reason: str) -> bool:
        current = self.get(name, version)
        if current is None or current.scan_id != scan_id:
            return False
        failed = current.model_copy(update={"status": ScanStatus.FAILED, "failure_reason": reason[:500] or "scan failed"})
        return self._replace_if_current(failed, (ScanStatus.PENDING, ScanStatus.SCANNING))

    def put_seeded(self, record: VerdictRecord) -> None:
        """Write a record scanned elsewhere (the local seed run). Overwrites unconditionally; callers decide."""
        self.table.put_item(Item=self._item(record))

    def record_completed(self, record: VerdictRecord) -> None:
        outcome = (record.verdict.value if record.verdict else record.status.value).lower()
        self.table.update_item(
            Key={"PK": "STATS", "SK": "ALL"},
            UpdateExpression="ADD scansCompleted :one, #outcome :one",
            ExpressionAttributeNames={"#outcome": outcome},
            ExpressionAttributeValues={":one": 1},
        )

    def stats(self) -> dict[str, int]:
        item = self.table.get_item(Key={"PK": "STATS", "SK": "ALL"}).get("Item") or {}
        keys = ("scansCompleted", "safe", "suspicious", "malicious", "skipped")
        return {key: int(item.get(key, 0)) for key in keys}

    def consume_scan_quota(self, client_id: str, now: datetime, per_client: int, per_day: int) -> str | None:
        """Count one new scan against today's limits. Returns None if allowed, or the reason it isn't."""
        day = now.astimezone(UTC).strftime("%Y-%m-%d")
        limits = (
            (f"CLIENT#{client_id}", per_client, "You've reached today's limit for new package scans. Try again tomorrow."),
            ("ALL", per_day, "PkgGuard has reached today's limit for new package scans. Try again tomorrow."),
        )
        for sort_key, maximum, reason in limits:
            try:
                self.table.update_item(
                    Key={"PK": f"LIMIT#{day}", "SK": sort_key},
                    UpdateExpression="SET expiresAt = :expires ADD scans :one",
                    ConditionExpression="attribute_not_exists(scans) OR scans < :max",
                    ExpressionAttributeValues={":one": 1, ":max": maximum, ":expires": _epoch(now + timedelta(days=2))},
                )
            except ClientError as error:
                if not _conditional_failed(error):
                    raise
                return reason
        return None

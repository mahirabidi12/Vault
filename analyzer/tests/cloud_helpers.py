"""Fake AWS resources (moto) matching infra/template.yaml. Keep the table schema in sync with the template."""

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import boto3
import httpx

from pkgguard_analyzer.cloud.api import Services
from pkgguard_analyzer.cloud.store import VerdictStore
from pkgguard_analyzer.schema import RanOn, ScanStatus, VerdictRecord

REGION = "ap-south-1"
TABLE = "verdicts"
BUCKET = "reports"
NOW = datetime(2026, 9, 17, 12, 0, tzinfo=UTC)


def create_table(dynamodb) -> None:
    dynamodb.create_table(
        TableName=TABLE,
        BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": n, "AttributeType": "S"} for n in ("PK", "SK", "GSI1PK", "GSI1SK", "scanId")],
        KeySchema=[{"AttributeName": "PK", "KeyType": "HASH"}, {"AttributeName": "SK", "KeyType": "RANGE"}],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "Feed",
                "KeySchema": [{"AttributeName": "GSI1PK", "KeyType": "HASH"}, {"AttributeName": "GSI1SK", "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"},
            },
            {"IndexName": "ByScanId", "KeySchema": [{"AttributeName": "scanId", "KeyType": "HASH"}], "Projection": {"ProjectionType": "ALL"}},
        ],
    )


@dataclass
class FakeCloud:
    dynamodb: object
    store: VerdictStore
    s3: object
    stepfunctions: object
    state_machine_arn: str

    def services(self, npm_packuments: dict[str, dict] | None = None, clock=lambda: NOW, **limits) -> Services:
        packuments = npm_packuments or {}

        def npm(request: httpx.Request) -> httpx.Response:
            name = request.url.path.lstrip("/").replace("%2F", "/").replace("%2f", "/")
            return httpx.Response(200, json=packuments[name]) if name in packuments else httpx.Response(404)

        return Services(
            store=self.store,
            s3=self.s3,
            stepfunctions=self.stepfunctions,
            http=httpx.Client(transport=httpx.MockTransport(npm)),
            bucket=BUCKET,
            state_machine_arn=self.state_machine_arn,
            clock=clock,
            **limits,
        )

    def executions(self) -> list[dict]:
        return self.stepfunctions.list_executions(stateMachineArn=self.state_machine_arn)["executions"]

    def execution_inputs(self) -> list[dict]:
        return [
            json.loads(self.stepfunctions.describe_execution(executionArn=e["executionArn"])["input"]) for e in self.executions()
        ]


def make_fake_cloud() -> FakeCloud:
    dynamodb = boto3.resource("dynamodb", region_name=REGION)
    create_table(dynamodb)
    s3 = boto3.client("s3", region_name=REGION)
    s3.create_bucket(Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION})
    stepfunctions = boto3.client("stepfunctions", region_name=REGION)
    arn = stepfunctions.create_state_machine(
        name="scan",
        definition=json.dumps({"StartAt": "Done", "States": {"Done": {"Type": "Succeed"}}}),
        roleArn="arn:aws:iam::123456789012:role/scan",
    )["stateMachineArn"]
    return FakeCloud(dynamodb, VerdictStore(dynamodb, TABLE), s3, stepfunctions, arn)


def record(name="express", version="4.18.2", status=ScanStatus.COMPLETE, verdict="SAFE", requested_at=NOW, analyzed_at=None, scan_id=None, **extra) -> VerdictRecord:
    data = {
        "package": {"ecosystem": "npm", "name": name, "version": version},
        "status": status,
        "scanId": scan_id or f"01J{abs(hash((name, version, str(requested_at)))) % 10**22:022d}",
        "requestedAt": requested_at,
        "ranOn": RanOn.CLOUD,
        "analyzerVersion": "0.1.0",
    }
    if status == ScanStatus.COMPLETE:
        data |= {"verdict": verdict, "confidence": "HIGH", "decidedBy": "rules", "summary": "s", "analyzedAt": analyzed_at or requested_at + timedelta(seconds=30)}
    if status in (ScanStatus.FAILED, ScanStatus.SKIPPED):
        data["failureReason"] = "boom"
    data.update(extra)
    return VerdictRecord.model_validate(data)


def http_event(method: str, path: str, query: dict | None = None, body: dict | None = None, ip: str = "1.2.3.4") -> dict:
    return {
        "rawPath": path,
        "queryStringParameters": query,
        "body": json.dumps(body) if body is not None else None,
        "isBase64Encoded": False,
        "requestContext": {"http": {"method": method, "sourceIp": ip}},
    }

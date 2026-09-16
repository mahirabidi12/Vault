"""Step Functions catch step: marks a scan FAILED when the scan task errors or times out."""

import json
import logging
import os
from functools import cache

import boto3

from pkgguard_analyzer.cloud.store import VerdictStore

log = logging.getLogger()
log.setLevel(logging.INFO)


@cache
def default_store() -> VerdictStore:
    return VerdictStore(boto3.resource("dynamodb"), os.environ["TABLE_NAME"])


def failure_reason(error: dict) -> str:
    """Step Functions passes {"Error": ..., "Cause": ...}; Lambda errors put a JSON object in Cause."""
    cause = error.get("Cause") or ""
    try:
        details = json.loads(cause)
        message = details.get("errorMessage") or cause
    except (ValueError, AttributeError):
        message = cause
    kind = error.get("Error") or "ScanError"
    return f"{kind}: {message}".strip(": ")[:500]


def handler(event: dict, context: object, store: VerdictStore | None = None) -> dict:
    store = store or default_store()
    reason = failure_reason(event.get("error") or {})
    saved = store.save_failed(event["name"], event["version"], event["scanId"], reason)
    log.info("marked scan %s failed (saved=%s): %s", event["scanId"], saved, reason)
    return {"scanId": event["scanId"], "status": "FAILED", "saved": saved}

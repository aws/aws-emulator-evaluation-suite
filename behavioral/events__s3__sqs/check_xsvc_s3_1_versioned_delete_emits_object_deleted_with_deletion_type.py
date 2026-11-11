"""xsvc-s3-1-versioned-delete-emits-object-deleted-with-deletion-type."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "xsvc-s3-1-versioned-delete-emits-object-deleted-with-deletion-type"
GROUP = "event-propagation"
SERVICES = ["events", "s3", "sqs"]

_CREATED = "Object Created"
_DELETED = "Object Deleted"
_MARKER = "Delete Marker Created"
_PERMANENT = "Permanently Deleted"

_DELIVERY_BUDGET_S = 180.0
_VERSIONING_WAIT_S = 60.0
_ABSENCE_FLOOR_BUDGET_S = 20.0
_ABSENCE_CEILING_BUDGET_S = 60.0


# The mailbox keeps EVERY body it drains so that waiting for one event never discards another's
# evidence.
class _Mailbox:
    def __init__(self, sqs, url: str, label: str):
        self.sqs, self.url, self.label = sqs, url, label
        self.bodies: list[str] = []

    def _pull(self, wait: int) -> None:
        resp = self.sqs.receive_message(
            QueueUrl=self.url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
        msgs = resp.get("Messages", [])
        if msgs:
            self.sqs.delete_message_batch(QueueUrl=self.url, Entries=[
                {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]}
                for i, m in enumerate(msgs)])
        self.bodies += [m["Body"] for m in msgs]

    def envelopes(self) -> list[dict]:
        return [json.loads(b) for b in self.bodies]

    def poll(self, predicate, budget_s: float) -> tuple[dict | None, float | None]:
        """(first matching envelope, seconds waited), or (None, None) if budget_s runs out."""
        started = time.monotonic()
        deadline = started + budget_s
        while True:
            hits = [e for e in self.envelopes() if predicate(e)]
            if hits:
                return hits[0], time.monotonic() - started
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None, None
            self._pull(max(1, min(5, int(remaining))))

    def seen(self) -> list[tuple]:
        return [(e.get("detail-type"), e["detail"].get("deletion-type"))
                for e in self.envelopes()]

    def wait_for(self, predicate, budget_s: float, what: str) -> tuple[dict, float]:
        env, latency = self.poll(predicate, budget_s)
        if env is None:
            raise AssertionError(
                f"{self.label}: {what} not delivered within {budget_s}s; "
                f"(detail-type, deletion-type) seen so far: {self.seen()!r}")
        return env, latency

    def soak(self, budget_s: float) -> None:
        deadline = time.monotonic() + budget_s
        while (remaining := deadline - time.monotonic()) > 0:
            self._pull(max(1, min(5, int(remaining))))


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
        items = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                 for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if items:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": items, "Quiet": True}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _make_bucket(ctx, s3) -> str:
    bucket = ctx.unique_name("sim2real-xsvc-s3d-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _make_queue(ctx, sqs, account: str) -> tuple[str, str]:
    """A queue whose policy admits default-bus rules; S3 service events land on the DEFAULT bus."""
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-s3d-"),
                           tags={"sim2real": CHECK})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(
        QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    sqs.set_queue_attributes(QueueUrl=url, Attributes={"Policy": json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "AllowEventBridge", "Effect": "Allow",
            "Principal": {"Service": "events.amazonaws.com"},
            "Action": "sqs:SendMessage", "Resource": arn,
            "Condition": {"ArnLike": {
                "aws:SourceArn": f"arn:aws:events:{ctx.region}:{account}:rule/*"}},
        }],
    })})
    return url, arn


def _make_rule(ctx, ev, pattern: dict, queue_arn: str) -> str:
    rule = ctx.unique_name("sim2real-xsvc-s3d-")
    ev.put_rule(Name=rule, State="ENABLED", EventPattern=json.dumps(pattern),
                Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))
    resp = ev.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["q"]))
    assert resp["FailedEntryCount"] == 0, (
        f"put_targets on {rule!r} reported failures: {resp.get('FailedEntries')!r}")
    return rule


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a versioned bucket a plain DeleteObject emits Object Deleted with deletion-type Delete
    Marker Created and a versioned one Permanently Deleted, both with reason DeleteObject and the
    version id acted on."""
    ev, s3, sqs = ctx.client("events"), ctx.client("s3"), ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _make_bucket(ctx, s3)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    deadline = time.monotonic() + _VERSIONING_WAIT_S
    while (status := s3.get_bucket_versioning(Bucket=bucket).get("Status")) != "Enabled":
        assert time.monotonic() < deadline, (
            f"bucket versioning never reported Enabled within {_VERSIONING_WAIT_S}s; "
            f"last Status {status!r}")
        time.sleep(2)

    created_url, created_arn = _make_queue(ctx, sqs, account)
    deleted_url, deleted_arn = _make_queue(ctx, sqs, account)
    _make_rule(ctx, ev, {"source": ["aws.s3"], "detail-type": [_CREATED],
                         "detail": {"bucket": {"name": [bucket]}}}, created_arn)
    _make_rule(ctx, ev, {"source": ["aws.s3"], "detail-type": [_DELETED],
                         "detail": {"bucket": {"name": [bucket]}}}, deleted_arn)

    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}})
    enabled = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in enabled, (
        f"bucket must be wired to EventBridge; GetBucketNotificationConfiguration -> {enabled!r}")

    created_box = _Mailbox(sqs, created_url, "Object Created queue")
    deleted_box = _Mailbox(sqs, deleted_url, "Object Deleted queue")
    key = "docs/report.txt"

    # Retried: a freshly created rule/target can silently drop its first delivered event
    # (PutRule/PutTargets return before the subscription path is fully live). Each retry mints a
    # NEW version, so an unobserved attempt's version is explicitly deleted (permanently, by
    # VersionId -- no marker) before the next attempt, keeping the version history clean for the
    # final listing assertion below.
    created_deadline = time.monotonic() + _DELIVERY_BUDGET_S
    created_env = created_latency = version_1 = None
    while created_latency is None:
        put = s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-versioned-bytes")
        candidate = put["VersionId"]
        assert candidate and candidate != "null", (
            f"a versioned bucket must mint a real VersionId, got {candidate!r}")
        remaining = created_deadline - time.monotonic()
        assert remaining > 0, (
            f"{_CREATED!r} for version {candidate!r} never delivered after retries; "
            f"(detail-type, deletion-type) seen: {created_box.seen()!r}")
        created_env, created_latency = created_box.poll(
            lambda e: e["detail"]["object"].get("version-id") == candidate,
            min(30.0, remaining))
        if created_env is None:
            s3.delete_object(Bucket=bucket, Key=key, VersionId=candidate)
            continue
        version_1 = candidate
    assert created_env["detail-type"] == _CREATED, (
        f"created rule delivered {created_env['detail-type']!r}")

    # --- delete 1: no VersionId -> a delete marker -----------------------------------------
    # Retried: this is the deleted-rule target's FIRST ever delivery, so the same
    # freshly-created-target drop risk applies. A dropped attempt's marker is permanently
    # removed (by its own VersionId -- that does not itself create a further marker) before
    # retrying, so a retry never leaves more than one marker behind.
    marker_deadline = time.monotonic() + _DELIVERY_BUDGET_S
    marker_env = marker_latency = marker_id = None
    while marker_latency is None:
        d1 = s3.delete_object(Bucket=bucket, Key=key)
        assert d1.get("DeleteMarker") is True, (
            f"DeleteObject without VersionId on a versioned bucket must create a marker; "
            f"response DeleteMarker={d1.get('DeleteMarker')!r}")
        candidate_marker = d1["VersionId"]
        remaining = marker_deadline - time.monotonic()
        assert remaining > 0, (
            f"marker {candidate_marker!r} never delivered after retries; "
            f"(detail-type, deletion-type) seen: {deleted_box.seen()!r}")
        marker_env, marker_latency = deleted_box.poll(
            lambda e, m=candidate_marker: (
                e["detail"].get("deletion-type") == _MARKER
                and e["detail"]["object"].get("version-id") == m),
            min(30.0, remaining))
        if marker_env is None:
            s3.delete_object(Bucket=bucket, Key=key, VersionId=candidate_marker)
            continue
        marker_id = candidate_marker
    assert marker_env["source"] == "aws.s3", f"source {marker_env['source']!r}"
    assert marker_env["detail-type"] == _DELETED, (
        f"detail-type must be {_DELETED!r}, got {marker_env['detail-type']!r}")
    assert marker_env["detail"]["reason"] == "DeleteObject", (
        f"reason must be 'DeleteObject', got {marker_env['detail']['reason']!r}")
    assert marker_env["detail"]["bucket"]["name"] == bucket, (
        f"detail.bucket.name {marker_env['detail']['bucket']['name']!r} != {bucket!r}")
    assert marker_env["detail"]["object"]["key"] == key, (
        f"detail.object.key {marker_env['detail']['object']['key']!r} != {key!r}")
    assert marker_env["detail"]["object"].get("version-id") == marker_id, (
        f"the marker event must carry the marker's version id {marker_id!r} that DeleteObject "
        f"returned; got {marker_env['detail']['object'].get('version-id')!r}")

    # --- delete 2: explicit VersionId -> permanent ------------------------------------------
    d2 = s3.delete_object(Bucket=bucket, Key=key, VersionId=version_1)
    assert d2.get("VersionId") == version_1, (
        f"DeleteObject(VersionId) must echo {version_1!r}, got {d2.get('VersionId')!r}")
    # Matched on version-id, not just deletion-type: a dropped-marker retry above cleans up its
    # stray marker by VersionId, which itself is a permanent deletion and emits its OWN
    # "Permanently Deleted" event (for the marker's version, not version_1) -- an unqualified
    # match here could grab that stray instead of the real one.
    perm_env, perm_latency = deleted_box.wait_for(
        lambda e: (e["detail"].get("deletion-type") == _PERMANENT
                  and e["detail"]["object"].get("version-id") == version_1),
        _DELIVERY_BUDGET_S, f"{_DELETED!r} with deletion-type {_PERMANENT!r} for {version_1!r}")
    assert perm_env["detail-type"] == _DELETED, (
        f"detail-type must be {_DELETED!r}, got {perm_env['detail-type']!r}")
    assert perm_env["detail"]["reason"] == "DeleteObject", (
        f"reason must be 'DeleteObject', got {perm_env['detail']['reason']!r}")
    assert perm_env["detail"]["object"]["key"] == key, (
        f"detail.object.key {perm_env['detail']['object']['key']!r} != {key!r}")
    assert perm_env["detail"]["object"].get("version-id") == version_1, (
        f"the permanent-delete event must carry the deleted version id {version_1!r}; got "
        f"{perm_env['detail']['object'].get('version-id')!r}")

    # Independent observable at S3: the marker survives, the original version is gone.
    listing = s3.list_object_versions(Bucket=bucket, Prefix=key)
    versions = [v["VersionId"] for v in listing.get("Versions", [])]
    markers = [m["VersionId"] for m in listing.get("DeleteMarkers", [])]
    assert versions == [] and markers == [marker_id], (
        f"after both deletes S3 must hold only the marker {marker_id!r}; "
        f"versions={versions!r} markers={markers!r}")

    # --- routing specificity ----------------------------------------------------------------
    window = min(max(_ABSENCE_FLOOR_BUDGET_S,
                     3.0 * max(created_latency, marker_latency, perm_latency)),
                 _ABSENCE_CEILING_BUDGET_S)
    created_box.soak(window / 2)
    deleted_box.soak(window / 2)
    wrong_on_deleted = sorted({e["detail-type"] for e in deleted_box.envelopes()} - {_DELETED})
    wrong_on_created = sorted({e["detail-type"] for e in created_box.envelopes()} - {_CREATED})
    assert wrong_on_deleted == [] and wrong_on_created == [], (
        f"each rule matches one detail-type; strays on the Deleted queue {wrong_on_deleted!r}, "
        f"on the Created queue {wrong_on_created!r}")
    kinds = sorted({e["detail"].get("deletion-type") for e in deleted_box.envelopes()})
    assert kinds == sorted([_MARKER, _PERMANENT]), (
        f"two deletes must yield exactly the two deletion-types; got {kinds!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

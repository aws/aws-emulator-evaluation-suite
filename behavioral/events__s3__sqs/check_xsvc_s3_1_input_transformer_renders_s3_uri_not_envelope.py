"""xsvc-s3-1-input-transformer-renders-s3-uri-not-envelope."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "xsvc-s3-1-input-transformer-renders-s3-uri-not-envelope"
GROUP = "event-propagation"
SERVICES = ["events", "s3", "sqs"]

_DELIVERY_BUDGET_S = 180.0


class _RawMailbox:
    """Keeps every raw message BODY, never JSON-decoded: the claim under test is that the
    transformed body is a bare string, so decoding it here would hide the very defect
    (an emulator that delivers the JSON envelope instead) this check exists to catch."""

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

    def poll(self, predicate, budget_s: float) -> str | None:
        """The first body matching predicate, or None if budget_s runs out first."""
        deadline = time.monotonic() + budget_s
        while True:
            hits = [b for b in self.bodies if predicate(b)]
            if hits:
                return hits[0]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
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
    bucket = ctx.unique_name("sim2real-xsvc-s3t-")
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
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-s3t-"),
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


def _make_rule(ctx, ev, pattern: dict, target: dict) -> str:
    rule = ctx.unique_name("sim2real-xsvc-s3t-")
    ev.put_rule(Name=rule, State="ENABLED", EventPattern=json.dumps(pattern),
                Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))
    resp = ev.put_targets(Rule=rule, Targets=[{"Id": "q", **target}])
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["q"]))
    assert resp["FailedEntryCount"] == 0, (
        f"put_targets on {rule!r} reported failures: {resp.get('FailedEntries')!r}")
    return rule


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A quoted s3://<b>/<k> InputTemplate makes an S3-sourced rule deliver the rendered JSON string
    of that URI to SQS, not the envelope, with the bucket and key the plain rule on the same bucket
    received."""
    ev, s3, sqs = ctx.client("events"), ctx.client("s3"), ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _make_bucket(ctx, s3)
    xform_url, xform_arn = _make_queue(ctx, sqs, account)
    raw_url, raw_arn = _make_queue(ctx, sqs, account)

    pattern = {"source": ["aws.s3"], "detail-type": ["Object Created"],
               "detail": {"bucket": {"name": [bucket]}}}
    _make_rule(ctx, ev, pattern, {
        "Arn": xform_arn,
        "InputTransformer": {
            "InputPathsMap": {"k": "$.detail.object.key", "b": "$.detail.bucket.name"},
            "InputTemplate": '"s3://<b>/<k>"',
        },
    })
    _make_rule(ctx, ev, pattern, {"Arn": raw_arn})

    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}})
    enabled = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in enabled, (
        f"bucket must be wired to EventBridge; GetBucketNotificationConfiguration -> {enabled!r}")

    xform_box = _RawMailbox(sqs, xform_url, "transformed-target queue")
    raw_box = _RawMailbox(sqs, raw_url, "plain-target queue (barrier/observable)")

    # Retried with a fresh key per attempt: a freshly created rule/target can silently drop its
    # first delivered event (PutRule/PutTargets return before the subscription path is fully
    # live), and the drop is per-TARGET, so a retry re-fires a brand new S3 event and requires
    # BOTH targets to confirm it before accepting the attempt.
    trigger_deadline = time.monotonic() + _DELIVERY_BUDGET_S
    attempt = 0
    key = raw_body = xform_body = None
    while key is None:
        attempt += 1
        candidate = f"reports/2026/summary-{attempt}.csv"
        s3.put_object(Bucket=bucket, Key=candidate, Body=b"sim2real-input-transformer-bytes")
        remaining = trigger_deadline - time.monotonic()
        assert remaining > 0, (
            f"event for {candidate!r} never reached both targets after {attempt} attempts; "
            f"{raw_box.label} bodies {raw_box.bodies!r}, {xform_box.label} bodies "
            f"{xform_box.bodies!r}")
        window = min(30.0, remaining)
        raw_body = raw_box.poll(
            lambda b, k=candidate: json.loads(b)["detail"]["object"]["key"] == k, window)
        if raw_body is None:
            continue
        xform_body = xform_box.poll(lambda b, k=candidate: b == f'"s3://{bucket}/{k}"', window)
        if xform_body is None:
            continue
        key = candidate

    # --- barrier: the plain rule's full envelope is the independent observable the ------------
    # expected URI is built from, not a value this check assumed in advance.
    envelope = json.loads(raw_body)
    assert envelope["detail-type"] == "Object Created", (
        f"barrier rule delivered {envelope['detail-type']!r}, not 'Object Created'")
    observed_key = envelope["detail"]["object"]["key"]
    observed_bucket = envelope["detail"]["bucket"]["name"]
    assert observed_key == key and observed_bucket == bucket, (
        f"barrier envelope must name the object just put; got bucket={observed_bucket!r} "
        f"key={observed_key!r}, expected bucket={bucket!r} key={key!r}")

    # --- the transformed body ------------------------------------------------------------------
    bare_uri = f"s3://{observed_bucket}/{observed_key}"
    expected_literal = f'"{bare_uri}"'
    assert xform_body == expected_literal, (
        f"InputTransformer must deliver exactly {expected_literal!r}; got {xform_body!r}")
    parsed = json.loads(xform_body)
    assert parsed == bare_uri, (
        f"the delivered body must round-trip through JSON to the bare URI {bare_uri!r}; "
        f"{xform_body!r} parsed as {parsed!r}")
    assert "detail-type" not in xform_body and "source" not in xform_body, (
        f"the transformed body must not carry envelope fields; got {xform_body!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

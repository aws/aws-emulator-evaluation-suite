"""object-restore-initiated-and-tags-added-carry-their-own-detail-types."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "object-restore-initiated-and-tags-added-carry-their-own-detail-types"
GROUP = 'eventing'
SERVICES = ['events', 's3', 'sqs']

_DELIVERY_BUDGET_S = 180.0
_MAX_CREDIBLE_DELIVERY_WAIT_S = 120.0
#: Absence window = max(floor, 3 x the slowest measured positive latency), capped by the ceiling.
_ABSENCE_FLOOR_BUDGET_S = 10.0
_ABSENCE_CEILING_BUDGET_S = 360.0

_CREATED = "Object Created"
_RESTORE_INITIATED = "Object Restore Initiated"
_TAGS_ADDED = "Object Tags Added"

#: One rule per detail-type, each with its own queue. Every queue is BOTH the positive control
#: for its own type and the absence target for the other two, on wiring that is identical except
#: for the one predicate under test.
_TYPES = (_CREATED, _RESTORE_INITIATED, _TAGS_ADDED)


def _receive(sqs, url: str, wait: int = 5) -> list[dict]:
    resp = sqs.receive_message(QueueUrl=url, MaxNumberOfMessages=10, WaitTimeSeconds=wait)
    msgs = resp.get("Messages", [])
    if msgs:
        sqs.delete_message_batch(QueueUrl=url, Entries=[
            {"Id": f"d{i}", "ReceiptHandle": m["ReceiptHandle"]} for i, m in enumerate(msgs)])
    return [json.loads(m["Body"]) for m in msgs]


def _queue(sqs, ctx, region: str, account: str) -> tuple[str, str]:
    """A queue whose policy admits default-bus rules; S3 service events land on the DEFAULT bus,
    whose rule ARNs carry no bus segment."""
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-behav-s3dt-"))["QueueUrl"]
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
                "aws:SourceArn": f"arn:aws:events:{region}:{account}:rule/*"}},
        }],
    })})
    return url, arn


def _collect(sqs, url: str, key: str, budget_s: float) -> list[dict]:
    """Every envelope on *url* naming object *key*, within *budget_s*. Returns as soon as one
    arrives; the caller decides whether one is enough."""
    got: list[dict] = []
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline and not got:
        got += [e for e in _receive(sqs, url)
                if e["detail"]["object"]["key"] == key]
    return got


def _collect_all(sqs, url: str, key: str, budget_s: float) -> list[dict]:
    """Every envelope naming *key* that arrives over the WHOLE of *budget_s* — the absence form,
    which must not short-circuit."""
    got: list[dict] = []
    deadline = time.monotonic() + budget_s
    while time.monotonic() < deadline:
        got += [e for e in _receive(sqs, url, wait=5)
                if e["detail"]["object"]["key"] == key]
    return got


def _poll(probe, predicate, timeout_s, interval_s=5.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """RestoreObject and PutObjectTagging reach EventBridge under their own detail-types, and a
    rule matching exactly one detail-type never receives another (S3 must not stamp every
    event "Object Created").

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-mapping-troubleshooting.html
    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventBridge.html
    """
    ev = ctx.client("events")
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-behav-s3dt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket,
                         CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "s3-eventbridge-detail-types"}]})

    # One single-detail-type rule and queue per type.
    queues: dict[str, str] = {}
    rules: dict[str, str] = {}
    for detail_type in _TYPES:
        url, arn = _queue(sqs, ctx, ctx.region, account)
        queues[detail_type] = url
        rule = ctx.unique_name("sim2real-behav-s3dt-")
        rules[detail_type] = rule
        ev.put_rule(
            Name=rule, State="ENABLED",
            EventPattern=json.dumps({
                "source": ["aws.s3"],
                "detail-type": [detail_type],
                "detail": {"bucket": {"name": [bucket]}},
            }),
            Tags=[{"Key": "sim2real", "Value": "s3-eventbridge-detail-types"}],
        )
        ctx.on_cleanup(lambda r=rule: ev.delete_rule(Name=r))
        resp = ev.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": arn}])
        ctx.on_cleanup(lambda r=rule: ev.remove_targets(Rule=r, Ids=["q"]))
        assert resp["FailedEntryCount"] == 0, (
            f"put_targets for the {detail_type!r} rule reported {resp['FailedEntryCount']} "
            f"failures: {resp.get('FailedEntries')!r}"
        )
        configured = ev.describe_rule(Name=rule)["EventPattern"]
        assert json.loads(configured)["detail-type"] == [detail_type], (
            f"the {detail_type!r} rule must match exactly that one detail-type; DescribeRule "
            f"reports {configured!r}"
        )

    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}})
    enabled = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in enabled, (
        f"the bucket must be wired to EventBridge before any event can be expected; "
        f"GetBucketNotificationConfiguration reports {enabled!r}"
    )

    key = ctx.unique_name("cold/obj-")

    # Object Created is the wiring's positive control; it runs BEFORE the restore because a
    # restore cannot be cancelled or repeated in one run.
    put_started = time.monotonic()
    put = s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-cold-bytes",
                        StorageClass="GLACIER")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    # EventBridge reports the ETag without the surrounding quotes PutObject returns.
    expected_etag = put["ETag"].strip('"')

    created = _collect(sqs, queues[_CREATED], key, _DELIVERY_BUDGET_S)
    created_latency_s = time.monotonic() - put_started
    assert created, (
        f"PutObject on an EventBridge-enabled bucket delivered no {_CREATED!r} envelope for "
        f"{key!r} within {_DELIVERY_BUDGET_S}s; the object exists (ETag {expected_etag!r}), so "
        f"the EMISSION is what is missing"
    )
    envelope = created[0]
    assert envelope["source"] == "aws.s3", (
        f"expected source 'aws.s3', got {envelope['source']!r}"
    )
    assert envelope["detail-type"] == _CREATED, (
        f"expected detail-type {_CREATED!r}, got {envelope['detail-type']!r}"
    )
    assert envelope["detail"]["bucket"]["name"] == bucket, (
        f"expected detail.bucket.name {bucket!r}, got {envelope['detail']['bucket']['name']!r}"
    )
    assert envelope["detail"]["object"]["etag"] == expected_etag, (
        f"expected detail.object.etag to be the ETag PutObject returned ({expected_etag!r}), got "
        f"{envelope['detail']['object']['etag']!r}"
    )
    assert envelope["detail"]["reason"] == "PutObject", (
        f"an object created by PutObject must carry reason 'PutObject', got "
        f"{envelope['detail']['reason']!r}"
    )

    # The object really is in the archive class, or "restore" below would be meaningless.
    head = s3.head_object(Bucket=bucket, Key=key)
    assert head["StorageClass"] == "GLACIER", (
        f"the object must be GLACIER for a restore to be possible; HeadObject reports "
        f"{head.get('StorageClass')!r}"
    )

    # --- leg 2: Object Restore Initiated ------------------------------------------------------
    restore_started = time.monotonic()
    s3.restore_object(Bucket=bucket, Key=key,
                      RestoreRequest={"Days": 1, "GlacierJobParameters": {"Tier": "Expedited"}})
    # A second observable that the restore started, so an empty restore queue is not blamed on it.
    ongoing = _poll(
        lambda: s3.head_object(Bucket=bucket, Key=key).get("Restore"),
        lambda r: r is not None and 'ongoing-request="true"' in r,
        timeout_s=60.0,
        what=f"HeadObject reporting an in-flight restore for {key!r}",
    )
    assert 'ongoing-request="true"' in ongoing, (
        f"HeadObject must report an in-flight restore, got Restore={ongoing!r}"
    )

    restored = _collect(sqs, queues[_RESTORE_INITIATED], key, _DELIVERY_BUDGET_S)
    restore_latency_s = time.monotonic() - restore_started
    assert restored, (
        f"RestoreObject delivered no {_RESTORE_INITIATED!r} envelope for {key!r} within "
        f"{_DELIVERY_BUDGET_S}s, even though HeadObject reports the restore in flight "
        f"({ongoing!r}) and the identical wiring already delivered {_CREATED!r} in "
        f"{created_latency_s:.1f}s"
    )
    assert restored[0]["detail-type"] == _RESTORE_INITIATED, (
        f"expected detail-type {_RESTORE_INITIATED!r}, got {restored[0]['detail-type']!r}"
    )
    assert restored[0]["source"] == "aws.s3", (
        f"expected source 'aws.s3', got {restored[0]['source']!r}"
    )
    assert restored[0]["detail"]["bucket"]["name"] == bucket, (
        f"expected detail.bucket.name {bucket!r}, got "
        f"{restored[0]['detail']['bucket']['name']!r}"
    )

    # --- leg 3: Object Tags Added -------------------------------------------------------------
    tag_started = time.monotonic()
    s3.put_object_tagging(Bucket=bucket, Key=key,
                          Tagging={"TagSet": [{"Key": "sim2real", "Value": "tagged"}]})
    tagged = _collect(sqs, queues[_TAGS_ADDED], key, _DELIVERY_BUDGET_S)
    tag_latency_s = time.monotonic() - tag_started
    assert tagged, (
        f"PutObjectTagging delivered no {_TAGS_ADDED!r} envelope for {key!r} within "
        f"{_DELIVERY_BUDGET_S}s; the tag is set (GetObjectTagging is the independent read below) "
        f"and the identical wiring already delivered {_CREATED!r} and {_RESTORE_INITIATED!r}"
    )
    assert tagged[0]["detail-type"] == _TAGS_ADDED, (
        f"expected detail-type {_TAGS_ADDED!r}, got {tagged[0]['detail-type']!r}"
    )
    tagset = s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
    assert tagset == [{"Key": "sim2real", "Value": "tagged"}], (
        f"the tag that produced the event must be readable at S3; GetObjectTagging reports "
        f"{tagset!r}"
    )

    # --- the mutual absences: each single-type rule received ONLY its own type ----------------
    measured = max(created_latency_s, restore_latency_s, tag_latency_s)
    assert measured <= _MAX_CREDIBLE_DELIVERY_WAIT_S, (
        f"the slowest positive control took {measured:.1f}s, above the "
        f"{_MAX_CREDIBLE_DELIVERY_WAIT_S}s this check will calibrate an absence against; refusing to "
        f"report an absence rather than widening the window silently"
    )
    absence_s = min(max(_ABSENCE_FLOOR_BUDGET_S, 3.0 * measured), _ABSENCE_CEILING_BUDGET_S)
    per_queue_s = absence_s / len(_TYPES)
    strays: dict[str, list[str]] = {}
    for detail_type in _TYPES:
        extra = _collect_all(sqs, queues[detail_type], key, per_queue_s)
        wrong = [e["detail-type"] for e in extra if e["detail-type"] != detail_type]
        if wrong:
            strays[detail_type] = wrong
    assert strays == {}, (
        f"each rule matches exactly one detail-type, so no queue may receive another; over "
        f"{absence_s:.0f}s the strays were {strays!r} (all three types were delivered in this "
        f"run, so every queue's wiring is proven)"
    )
    depths = {
        detail_type: sqs.get_queue_attributes(
            QueueUrl=queues[detail_type],
            AttributeNames=["ApproximateNumberOfMessages",
                            "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        for detail_type in _TYPES
    }
    nonempty = {t: d for t, d in depths.items()
                if d != {"ApproximateNumberOfMessages": "0",
                         "ApproximateNumberOfMessagesNotVisible": "0"}}
    assert nonempty == {}, (
        f"every single-type queue must be empty once its own event has been consumed; these are "
        f"not: {nonempty!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

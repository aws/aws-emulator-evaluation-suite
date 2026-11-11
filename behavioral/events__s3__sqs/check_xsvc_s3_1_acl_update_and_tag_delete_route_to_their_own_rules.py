"""xsvc-s3-1-acl-update-and-tag-delete-route-to-their-own-rules."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "xsvc-s3-1-acl-update-and-tag-delete-route-to-their-own-rules"
GROUP = "event-propagation"
SERVICES = ["events", "s3", "sqs"]

_CREATED = "Object Created"
_ACL = "Object ACL Updated"
_TAGS_DELETED = "Object Tags Deleted"
#: One rule and one queue per detail-type. Every queue is the positive control for its own
#: type and an absence target for the other two, on wiring identical except for that predicate.
_TYPES = (_CREATED, _ACL, _TAGS_DELETED)

_DELIVERY_BUDGET_S = 180.0
# The slowest positive delivery this check calibrates an absence window against.
_MAX_CREDIBLE_DELIVERY_WAIT_S = 180.0
_ABSENCE_FLOOR_BUDGET_S = 30.0
_ABSENCE_CEILING_BUDGET_S = 90.0


# The mailbox keeps every body it drains so waiting for one event never discards another's.
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

    def types(self) -> set[str]:
        return {e["detail-type"] for e in self.envelopes()}

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

    def soak(self, budget_s: float) -> None:
        deadline = time.monotonic() + budget_s
        while (remaining := deadline - time.monotonic()) > 0:
            self._pull(max(1, min(5, int(remaining))))

    def depth(self) -> dict:
        return self.sqs.get_queue_attributes(
            QueueUrl=self.url,
            AttributeNames=["ApproximateNumberOfMessages",
                            "ApproximateNumberOfMessagesNotVisible"])["Attributes"]


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
    """ACLs ENABLED (BucketOwnerPreferred) so PutObjectAcl is an ordinary call, not one the
    bucket-owner-enforced default would refuse."""
    bucket = ctx.unique_name("sim2real-xsvc-s3a-")
    kwargs = {"ObjectOwnership": "BucketOwnerPreferred"}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": CHECK}]})
    return bucket


def _make_queue(ctx, sqs, account: str) -> tuple[str, str]:
    """A queue whose policy admits default-bus rules; S3 service events land on the DEFAULT bus."""
    url = sqs.create_queue(QueueName=ctx.unique_name("sim2real-xsvc-s3a-"),
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
    rule = ctx.unique_name("sim2real-xsvc-s3a-")
    ev.put_rule(Name=rule, State="ENABLED", EventPattern=json.dumps(pattern),
                Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ev.delete_rule(Name=rule))
    resp = ev.put_targets(Rule=rule, Targets=[{"Id": "q", "Arn": queue_arn}])
    ctx.on_cleanup(lambda: ev.remove_targets(Rule=rule, Ids=["q"]))
    assert resp["FailedEntryCount"] == 0, (
        f"put_targets on {rule!r} reported failures: {resp.get('FailedEntries')!r}")
    return rule


@tags("axis:negative-delivery", "cap:c2", "concern:data-plane", "concern:e2e",
      "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutObjectAcl emits "Object ACL Updated" and DeleteObjectTagging "Object Tags Deleted", each
    reaching only the rule naming its detail-type; after a soak every queue holds only its own type,
    and S3 reads back a single FULL_CONTROL grant and an empty tag set.

    Reference: https://docs.aws.amazon.com/AmazonS3/latest/userguide/ev-mapping-troubleshooting.html
    """
    ev, s3, sqs = ctx.client("events"), ctx.client("s3"), ctx.client("sqs")
    account = ctx.client("sts").get_caller_identity()["Account"]

    bucket = _make_bucket(ctx, s3)
    boxes: dict[str, _Mailbox] = {}
    for detail_type in _TYPES:
        url, arn = _make_queue(ctx, sqs, account)
        _make_rule(ctx, ev, {"source": ["aws.s3"], "detail-type": [detail_type],
                             "detail": {"bucket": {"name": [bucket]}}}, arn)
        boxes[detail_type] = _Mailbox(sqs, url, f"{detail_type!r} queue")

    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}})
    enabled = s3.get_bucket_notification_configuration(Bucket=bucket)
    assert "EventBridgeConfiguration" in enabled, (
        f"bucket must be wired to EventBridge; GetBucketNotificationConfiguration -> {enabled!r}")

    key = "shared/doc.txt"
    # Retried: a freshly created rule/target can silently drop its first delivered event
    # (PutRule/PutTargets return before the subscription path is fully live), and re-issuing the
    # same PutObject is safe here (unversioned bucket, idempotent overwrite).
    created_deadline = time.monotonic() + _DELIVERY_BUDGET_S
    created_latency = None
    while created_latency is None:
        s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-acl-tag-bytes",
                      Tagging="team=sim2real&stage=draft")
        remaining = created_deadline - time.monotonic()
        assert remaining > 0, (
            f"{_CREATED!r} for {key!r} never delivered after retries; detail-types seen: "
            f"{sorted(boxes[_CREATED].types())!r}")
        _, created_latency = boxes[_CREATED].poll(
            lambda e: e["detail"]["object"]["key"] == key, min(30.0, remaining))
    tagset = s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
    assert sorted((t["Key"], t["Value"]) for t in tagset) == [
        ("stage", "draft"), ("team", "sim2real")], (
        f"the object must carry the two tags set at PutObject; GetObjectTagging -> {tagset!r}")

    # --- ACL update --------------------------------------------------------------------------
    # Retried: PutObjectAcl is idempotent/safe to repeat, and the same freshly-created-target
    # drop risk applies to this rule's first delivery too.
    acl_deadline = time.monotonic() + _DELIVERY_BUDGET_S
    acl_env = acl_latency = None
    while acl_latency is None:
        s3.put_object_acl(Bucket=bucket, Key=key, ACL="bucket-owner-full-control")
        remaining = acl_deadline - time.monotonic()
        assert remaining > 0, (
            f"{_ACL!r} for {key!r} never delivered after retries; detail-types seen: "
            f"{sorted(boxes[_ACL].types())!r}")
        acl_env, acl_latency = boxes[_ACL].poll(
            lambda e: e["detail"]["object"]["key"] == key, min(30.0, remaining))
    assert acl_env["source"] == "aws.s3", f"source must be 'aws.s3', got {acl_env['source']!r}"
    assert acl_env["detail-type"] == _ACL, (
        f"detail-type must be {_ACL!r}, got {acl_env['detail-type']!r}")
    assert acl_env["detail"]["bucket"]["name"] == bucket, (
        f"detail.bucket.name {acl_env['detail']['bucket']['name']!r} != {bucket!r}")
    grants = s3.get_object_acl(Bucket=bucket, Key=key)["Grants"]
    assert [g["Permission"] for g in grants] == ["FULL_CONTROL"], (
        f"after PutObjectAcl the object must hold one FULL_CONTROL grant; got {grants!r}")
    # Barrier: the ACL event has arrived; no tagging-delete has been issued yet.
    assert _TAGS_DELETED not in boxes[_TAGS_DELETED].types(), (
        f"{_TAGS_DELETED!r} arrived before DeleteObjectTagging was called: "
        f"{boxes[_TAGS_DELETED].bodies!r}")

    # --- tag delete --------------------------------------------------------------------------
    # Retried: DeleteObjectTagging on an already-untagged object is a no-op that need not
    # re-fire the event, so a retry re-adds a tag (a genuine non-empty-to-empty transition)
    # before deleting it again.
    tags_deadline = time.monotonic() + _DELIVERY_BUDGET_S
    tags_env = tags_latency = None
    s3.delete_object_tagging(Bucket=bucket, Key=key)
    while tags_latency is None:
        remaining = tags_deadline - time.monotonic()
        assert remaining > 0, (
            f"{_TAGS_DELETED!r} for {key!r} never delivered after retries; detail-types seen: "
            f"{sorted(boxes[_TAGS_DELETED].types())!r}")
        tags_env, tags_latency = boxes[_TAGS_DELETED].poll(
            lambda e: e["detail"]["object"]["key"] == key, min(30.0, remaining))
        if tags_latency is None:
            s3.put_object_tagging(Bucket=bucket, Key=key, Tagging={
                "TagSet": [{"Key": "retry", "Value": "tag"}]})
            s3.delete_object_tagging(Bucket=bucket, Key=key)
    assert tags_env["detail-type"] == _TAGS_DELETED, (
        f"detail-type must be {_TAGS_DELETED!r}, got {tags_env['detail-type']!r}")
    assert tags_env["detail"]["bucket"]["name"] == bucket, (
        f"detail.bucket.name {tags_env['detail']['bucket']['name']!r} != {bucket!r}")
    after = s3.get_object_tagging(Bucket=bucket, Key=key)["TagSet"]
    assert after == [], f"DeleteObjectTagging must empty the tag set; got {after!r}"

    # --- routing specificity: each queue holds only its own type -----------------------------
    measured = max(created_latency, acl_latency, tags_latency)
    assert measured <= _MAX_CREDIBLE_DELIVERY_WAIT_S, (
        f"slowest positive delivery took {measured:.1f}s, above the "
        f"{_MAX_CREDIBLE_DELIVERY_WAIT_S}s this check will calibrate an absence against")
    window = min(max(_ABSENCE_FLOOR_BUDGET_S, 3.0 * measured), _ABSENCE_CEILING_BUDGET_S)
    for detail_type in _TYPES:
        boxes[detail_type].soak(window / len(_TYPES))
    strays = {t: sorted(boxes[t].types() - {t}) for t in _TYPES if boxes[t].types() - {t}}
    assert strays == {}, (
        f"each single-type rule must receive only its own detail-type; over {window:.0f}s the "
        f"strays were {strays!r} (all three types were delivered, so every queue is wired)")
    depths = {t: boxes[t].depth() for t in _TYPES}
    nonempty = {t: d for t, d in depths.items()
                if d != {"ApproximateNumberOfMessages": "0",
                         "ApproximateNumberOfMessagesNotVisible": "0"}}
    assert nonempty == {}, f"every queue must be drained after the soak; not: {nonempty!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

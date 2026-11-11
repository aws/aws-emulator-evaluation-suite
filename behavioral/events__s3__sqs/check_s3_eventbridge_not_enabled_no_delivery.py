"""s3-eventbridge-not-enabled-no-delivery."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-eventbridge-not-enabled-no-delivery"

GROUP = "overly-permissive"

SERVICES = ["events", "s3", "sqs"]


def _is_s3_test_event(body: object) -> bool:
    """True for S3's one-off destination-validation handshake message.

    When a queue is first attached as an S3 notification destination, S3 posts
    {"Service":"Amazon S3","Event":"s3:TestEvent", ...} to prove it can write to
    the queue. It carries no "Records" and is NOT an object event, so it must
    never be mistaken for one (nor counted as an over-delivery).
    """
    return isinstance(body, dict) and body.get("Event") == "s3:TestEvent"


def _bucket_name_of(body: object) -> str | None:
    if not isinstance(body, dict):
        return None
    return body.get("detail", {}).get("bucket", {}).get("name")


def _drain_twin(
    ctx,
    queue_url: str,
    control_bucket: str,
    subject_bucket: str,
    control_timeout_s: float = 300.0,
    hold_after_control_s: float = 45.0,
) -> tuple[bool, list[dict]]:
    """Prove delivery is alive on *control_bucket* while watching *subject_bucket* for a leak.

    A bare absence window cannot tell "correctly withheld" from "this target never delivers
    anything, for anyone" -- both look identical from the subject bucket alone. So this drives
    the SAME rule/target/queue with a twin bucket that DOES have EventBridgeConfiguration
    enabled, re-putting into it (S3->EventBridge enablement is documented as eventually
    consistent, up to ~5 minutes) until a control message lands. Only once the pipe is proven
    live does absence from subject_bucket mean anything; the hold continues a further
    *hold_after_control_s* past that point to catch a late/racy leak.

    Returns (control_delivered, subject_messages_seen).
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + control_timeout_s
    control_delivered = False
    hold_deadline = 0.0
    subject_messages: list[dict] = []
    attempt = 0
    while control_delivered and time.monotonic() < hold_deadline or (
        not control_delivered and time.monotonic() < deadline
    ):
        if not control_delivered:
            attempt += 1
            s3.put_object(
                Bucket=control_bucket, Key=f"control-probe-{attempt}.txt", Body=b"data"
            )
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=10,
            WaitTimeSeconds=5,
            MessageAttributeNames=["All"],
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if _is_s3_test_event(body):
                continue
            name = _bucket_name_of(body)
            if name == subject_bucket:
                subject_messages.append({"body": body})
            elif name == control_bucket and not control_delivered:
                control_delivered = True
                hold_deadline = time.monotonic() + hold_after_control_s
        if subject_messages:
            break
    return control_delivered, subject_messages


def _sqs_policy_for_events(queue_arn: str, rule_arn: str | None = None) -> dict:
    statement = {
        "Sid": "AllowEventsSendMessage",
        "Effect": "Allow",
        "Principal": {"Service": "events.amazonaws.com"},
        "Action": "sqs:SendMessage",
        "Resource": queue_arn,
    }
    if rule_arn:
        statement["Condition"] = {"ArnEquals": {"aws:SourceArn": rule_arn}}
    return {"Version": "2012-10-17", "Statement": [statement]}


def _set_queue_policy(ctx, queue_url: str, policy: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


def _rule_arn(ctx, rule_name: str, bus_name: str | None = None) -> str:
    kwargs = {"Name": rule_name}
    if bus_name:
        kwargs["EventBusName"] = bus_name
    return ctx.client("events").describe_rule(**kwargs)["Arn"]


@tags("axis:negative-delivery", "cap:c1", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Without EventBridgeConfiguration enabled on the bucket, S3 must not emit events to EB --
    proven against a twin control bucket, wired identically but WITH EventBridgeConfiguration
    enabled, so a target that delivers nothing to anyone cannot pass by coincidence."""
    s3 = ctx.client("s3")
    events = ctx.client("events")
    subject_bucket = _create_bucket(ctx)
    control_bucket = _create_bucket(ctx)
    queue = _create_queue(ctx)

    s3.put_bucket_notification_configuration(
        Bucket=control_bucket["name"],
        NotificationConfiguration={"EventBridgeConfiguration": {}},
    )
    # NOTE: intentionally skip put_bucket_notification_configuration(EventBridgeConfiguration={})
    # for subject_bucket -- that omission is the subject under test.

    rule_name = ctx.unique_name("s3-eb-disabled-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["aws.s3"],
                "detail-type": ["Object Created"],
                "detail": {
                    "bucket": {"name": [subject_bucket["name"], control_bucket["name"]]}
                },
            }
        ),
    )
    ctx.on_cleanup(lambda: ctx.client("events").delete_rule(Name=rule_name))
    rule_arn = _rule_arn(ctx, rule_name)

    _set_queue_policy(ctx, queue["url"], _sqs_policy_for_events(queue["arn"], rule_arn))
    events.put_targets(
        Rule=rule_name, Targets=[{"Id": "sqs-target", "Arn": queue["arn"]}]
    )
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["sqs-target"]))

    s3.put_object(Bucket=subject_bucket["name"], Key="no-eb.txt", Body=b"data")

    control_delivered, subject_messages = _drain_twin(
        ctx, queue["url"], control_bucket["name"], subject_bucket["name"]
    )
    assert control_delivered, (
        "positive control failed: S3->EventBridge delivery for control_bucket (which HAS "
        "EventBridgeConfiguration enabled) never reached the queue, so absence for "
        "subject_bucket cannot be attributed to correct behavior rather than a dead pipe"
    )
    assert not subject_messages, (
        "SQS received an S3 event via EventBridge even though EventBridgeConfiguration "
        f"was never enabled on subject_bucket: {subject_messages}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    """S3 buckets must be emptied before deletion — a raw delete_bucket on a non-empty bucket fails
    with BucketNotEmpty and (since teardown swallows errors) leaks the bucket. Purge objects AND all
    versions/delete-markers (versioning may be on), then delete."""
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket):
            targets = [
                {"Key": o["Key"], "VersionId": o["VersionId"]}
                for o in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if targets:
                failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": targets}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError:
        try:
            p2 = s3.get_paginator("list_objects_v2")
            for page in p2.paginate(Bucket=bucket):
                keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
                if keys:
                    failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
                    if failed:
                        raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise
    s3.delete_bucket(Bucket=bucket)


def _create_queue(ctx, fifo: bool = False, **attrs: str) -> dict[str, str]:
    """Create an SQS queue (registers delete_queue teardown). Returns {name,url,arn}."""
    base = _xname(ctx, "q")
    name = f"{base}.fifo" if fifo else base
    sqs = ctx.client("sqs")
    create_attrs = dict(attrs)
    if fifo:
        create_attrs["FifoQueue"] = "true"
    resp = sqs.create_queue(
        QueueName=name, Attributes=create_attrs, tags=_xsvc_resource_tags()
    )
    url = resp["QueueUrl"]
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return {"name": name, "url": url, "arn": arn}


def _create_bucket(ctx) -> dict[str, str]:
    """Create an S3 bucket (registers empty-then-delete teardown). Returns {name,arn}."""
    name = _xname(ctx, "bkt")
    s3 = ctx.client("s3")
    create_kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        create_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**create_kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    try:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})
    except ClientError:
        pass
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _wait_for_messages(ctx, queue_url, expected_count=1, timeout_s=60.0, delete=True):
    """Poll SQS until expected_count messages arrive; return them (raises on timeout)."""
    sqs = ctx.client("sqs")
    messages: list[dict[str, Any]] = []
    deadline = time.monotonic() + timeout_s
    while len(messages) < expected_count and time.monotonic() < deadline:
        remaining = max(1, int(deadline - time.monotonic()))
        resp = sqs.receive_message(
            QueueUrl=queue_url,
            MaxNumberOfMessages=min(10, expected_count - len(messages)),
            WaitTimeSeconds=min(5, remaining),
            MessageAttributeNames=["All"],
        )
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = msg["Body"]
            messages.append(
                {
                    "body": body,
                    "message_id": msg["MessageId"],
                    "receipt_handle": msg["ReceiptHandle"],
                    "attributes": msg.get("MessageAttributes", {}),
                }
            )
            if delete:
                sqs.delete_message(
                    QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"]
                )
    if len(messages) < expected_count:
        raise AssertionError(
            f"Expected {expected_count} messages, got {len(messages)} within {timeout_s}s"
        )
    return messages


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""s3-eventbridge-to-sqs."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-eventbridge-to-sqs"

GROUP = "event-propagation"

SERVICES = ["events", "s3", "sqs"]


def _put_until_delivered(
    ctx,
    bucket: str,
    key: str,
    queue_url: str,
    timeout_s: float = 300,
) -> list[dict]:
    """Re-put an object until its S3->EventBridge notification reaches the queue.

    Enabling EventBridgeConfiguration on a bucket is eventually consistent: AWS
    documents that it can take ~5 minutes before events actually start flowing.
    A single put right after enabling is therefore racy, so we keep writing new
    object versions until a notification lands (or the deadline passes).
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        s3.put_object(Bucket=bucket, Key=key, Body=f"attempt-{attempt}".encode())
        inner = time.monotonic() + 20
        while time.monotonic() < inner and time.monotonic() < deadline:
            resp = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=10,
                WaitTimeSeconds=5,
                MessageAttributeNames=["All"],
            )
            msgs = resp.get("Messages", [])
            if msgs:
                out = []
                for m in msgs:
                    try:
                        body = json.loads(m["Body"])
                    except (json.JSONDecodeError, ValueError):
                        body = m["Body"]
                    out.append(
                        {"body": body, "attributes": m.get("MessageAttributes", {})}
                    )
                    sqs.delete_message(
                        QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"]
                    )
                return out
    raise AssertionError(
        f"no S3->EventBridge notification reached the queue within {timeout_s}s "
        f"after {attempt} put_object attempts"
    )


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


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """S3 EventBridge notifications route Object Created events to SQS via a rule."""
    s3 = ctx.client("s3")
    events = ctx.client("events")
    bucket = _create_bucket(ctx)
    queue = _create_queue(ctx)

    s3.put_bucket_notification_configuration(
        Bucket=bucket["name"],
        NotificationConfiguration={"EventBridgeConfiguration": {}},
    )

    rule_name = ctx.unique_name("s3-eb-rule-")
    events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(
            {
                "source": ["aws.s3"],
                "detail-type": ["Object Created"],
                "detail": {"bucket": {"name": [bucket["name"]]}},
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

    s3.put_object(Bucket=bucket["name"], Key="via-eventbridge.txt", Body=b"data")

    messages = _put_until_delivered(
        ctx, bucket["name"], "via-eventbridge.txt", queue["url"], timeout_s=300
    )
    assert messages, "expected S3->EventBridge event in SQS queue"
    detail = messages[0]["body"]
    assert detail["source"] == "aws.s3", f"expected source aws.s3, got {detail.get('source')!r}"
    assert detail["detail"]["bucket"]["name"] == bucket["name"], (
        f"expected bucket {bucket['name']!r} in event detail, got {detail['detail']['bucket'].get('name')!r}"
    )
    assert detail["detail"]["object"]["key"] == "via-eventbridge.txt", (
        f"expected object key 'via-eventbridge.txt', got {detail['detail']['object'].get('key')!r}"
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

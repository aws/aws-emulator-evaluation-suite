"""sqs-queue-policy-sourcearn-scoping."""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-queue-policy-sourcearn-scoping"

GROUP = "arn-resolution"

SERVICES = ["events", "s3", "sqs"]


def _sqs_policy_for_s3(queue_arn: str, bucket_arn: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowS3SendMessage",
                "Effect": "Allow",
                "Principal": {"Service": "s3.amazonaws.com"},
                "Action": "sqs:SendMessage",
                "Resource": queue_arn,
                "Condition": {"ArnEquals": {"aws:SourceArn": bucket_arn}},
            }
        ],
    }


def _set_queue_policy(ctx, queue_url: str, policy: dict) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url, Attributes={"Policy": json.dumps(policy)}
    )


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A queue policy scoped to bucket A's ARN must not authorize notifications from bucket B."""
    s3 = ctx.client("s3")
    bucket_a = _create_bucket(ctx)
    bucket_b = _create_bucket(ctx)
    queue = _create_queue(ctx)

    # Policy only allows SourceArn == bucket_a
    _set_queue_policy(
        ctx, queue["url"], _sqs_policy_for_s3(queue["arn"], bucket_a["arn"])
    )

    # Configuring bucket_a's notifications should succeed (source arn matches policy), and an
    # independent read (not the mutating call's own response) must show it actually landed.
    s3.put_bucket_notification_configuration(
        Bucket=bucket_a["name"],
        NotificationConfiguration={
            "QueueConfigurations": [
                {"QueueArn": queue["arn"], "Events": ["s3:ObjectCreated:*"]}
            ]
        },
    )
    positive_read = s3.get_bucket_notification_configuration(Bucket=bucket_a["name"])
    positive_arns = {
        c["QueueArn"] for c in positive_read.get("QueueConfigurations", [])
    }
    assert queue["arn"] in positive_arns, (
        f"expected {queue['arn']!r} in bucket_a's saved notification config after a "
        f"policy-matching put, got {positive_arns!r}"
    )

    # Configuring bucket_b's notifications to the SAME queue must fail: the queue policy
    # does not authorize bucket_b's ARN as a SourceArn.
    err = _client_error(
        lambda: s3.put_bucket_notification_configuration(
            Bucket=bucket_b["name"],
            NotificationConfiguration={
                "QueueConfigurations": [
                    {"QueueArn": queue["arn"], "Events": ["s3:ObjectCreated:*"]}
                ]
            },
        )
    )
    assert err == ("InvalidArgument", _UNVALIDATED_DESTINATION), (
        f"expected InvalidArgument {_UNVALIDATED_DESTINATION!r} rejecting bucket_b (queue policy "
        f"is scoped to bucket_a's ARN, not bucket_b's), got {err!r}"
    )

    # The rejected call must not have landed: an independent read shows bucket_b still has
    # no saved queue configuration.
    negative_read = s3.get_bucket_notification_configuration(Bucket=bucket_b["name"])
    assert not negative_read.get("QueueConfigurations", []), (
        f"bucket_b must have no saved queue configuration after the rejected put, got "
        f"{negative_read.get('QueueConfigurations')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_UNVALIDATED_DESTINATION = "Unable to validate the following destination configurations"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _client_error(fn) -> tuple[str, str]:
    """(error code, message) of a call expected to fail; RAISES if the call succeeds."""
    try:
        resp = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but succeeded: {resp!r}")


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

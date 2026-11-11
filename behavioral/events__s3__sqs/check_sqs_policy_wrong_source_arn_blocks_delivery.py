"""sqs-policy-wrong-source-arn-blocks-delivery."""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sqs-policy-wrong-source-arn-blocks-delivery"

GROUP = "overly-permissive"

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


@tags(
    "axis:rejection",
    "cap:c7",
    "concern:eventing",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A queue policy whose SourceArn names a decoy bucket lets the decoy configure
    notifications but refuses the real bucket with InvalidArgument and its exact message,
    storing no configuration."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    decoy_bucket = _create_bucket(ctx)
    queue = _create_queue(ctx)

    def _put_notification(bucket_name: str):
        return s3.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration={
                "QueueConfigurations": [
                    {"QueueArn": queue["arn"], "Events": ["s3:ObjectCreated:*"]}
                ]
            },
        )

    # Policy is scoped to decoy_bucket's ARN, NOT the real bucket being configured. Neither
    # bucket has ever been validated against this queue, so both attempts get a fresh check.
    _set_queue_policy(
        ctx, queue["url"], _sqs_policy_for_s3(queue["arn"], decoy_bucket["arn"])
    )

    # Twin control, same instant, same fixed policy: the bucket the policy actually names
    # must be authorized — proving the policy is otherwise functional, not just universally
    # rejecting — while the real bucket, named nowhere in the policy, must not be.
    # Positive control: decoy_bucket's own ARN is the policy's SourceArn condition, so its
    # notification config is accepted (a refusal raises here).
    _put_notification(decoy_bucket["name"])

    err = _client_error(lambda: _put_notification(bucket["name"]))
    assert err == ("InvalidArgument", _UNVALIDATED_DESTINATION), (
        f"expected InvalidArgument {_UNVALIDATED_DESTINATION!r}: queue policy SourceArn "
        f"condition references decoy_bucket's ARN, not the real bucket being configured, "
        f"got {err!r}"
    )

    # Terminal reads, independent of the mutating calls: decoy_bucket carries the queue
    # config it was authorized for; the real bucket carries none — the rejection was not
    # silently partially applied.
    decoy_live = s3.get_bucket_notification_configuration(Bucket=decoy_bucket["name"])
    assert decoy_live.get("QueueConfigurations"), (
        f"decoy_bucket should show the queue configuration its policy authorized: {decoy_live}"
    )
    live = s3.get_bucket_notification_configuration(Bucket=bucket["name"])
    assert not live.get("QueueConfigurations"), (
        f"rejected notification config must not have been applied to the real bucket: {live}"
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
    """S3 buckets must be emptied before deletion: DeleteBucket on a non-empty bucket fails
    with BucketNotEmpty. Purge objects AND all versions/delete-markers (versioning may be on),
    then delete."""
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

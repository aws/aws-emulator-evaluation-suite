"""s3-notification-without-queue-policy-fails."""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-notification-without-queue-policy-fails"

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


def _set_queue_policy(ctx, queue_url: str, policy: dict | None) -> None:
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"Policy": json.dumps(policy) if policy else ""},
    )


def _configured_queue_arns(ctx, bucket: str) -> list[str]:
    resp = ctx.client("s3").get_bucket_notification_configuration(Bucket=bucket)
    return [q["QueueArn"] for q in resp.get("QueueConfigurations", [])]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration with a queue lacking a policy fails with
    InvalidArgument and its exact message and leaves the stored configuration unchanged; once
    granted the call succeeds."""
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx)
    ok_queue = _create_queue(ctx)
    bad_queue = _create_queue(ctx)  # deliberately never given a policy

    def put(queue):
        s3.put_bucket_notification_configuration(
            Bucket=bucket["name"],
            NotificationConfiguration={
                "QueueConfigurations": [
                    {"QueueArn": queue["arn"], "Events": ["s3:ObjectCreated:*"]}
                ]
            },
        )

    # Positive control: a queue whose policy grants s3.amazonaws.com is accepted, and the
    # config is visible at the destination via an independent read.
    _set_queue_policy(ctx, ok_queue["url"], _sqs_policy_for_s3(ok_queue["arn"], bucket["arn"]))
    put(ok_queue)
    assert _configured_queue_arns(ctx, bucket["name"]) == [ok_queue["arn"]], (
        "positive control failed: notification config did not take effect with a "
        "permissioned queue policy"
    )

    # Break exactly one thing: point at a queue that has no permission policy at all.
    err = _client_error(lambda: put(bad_queue))
    assert err == ("InvalidArgument", _UNVALIDATED_DESTINATION), (
        f"expected InvalidArgument {_UNVALIDATED_DESTINATION!r} when the queue policy grants no "
        f"permission, got {err!r}"
    )
    assert _configured_queue_arns(ctx, bucket["name"]) == [ok_queue["arn"]], (
        "the rejected notification config must not take effect at the destination — the "
        "prior (positive-control) config must still be the one in force"
    )

    # Restore: grant the policy and prove the IDENTICAL call now succeeds.
    _set_queue_policy(ctx, bad_queue["url"], _sqs_policy_for_s3(bad_queue["arn"], bucket["arn"]))
    put(bad_queue)
    assert _configured_queue_arns(ctx, bucket["name"]) == [bad_queue["arn"]], (
        "restore failed: the identical call did not succeed once the queue policy was granted"
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

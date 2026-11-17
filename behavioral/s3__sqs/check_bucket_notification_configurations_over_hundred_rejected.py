"""bucket-notification-configurations-over-hundred-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "bucket-notification-configurations-over-hundred-rejected"
GROUP = "notifications"
SERVICES = ["s3", "sqs"]

#: Event notification configurations are capped at a fixed, non-adjustable 100 per bucket.
_MAX_CONFIGS = 100

#: S3's refusal of a notification configuration set past that cap.
_TOO_MANY_CONFIGS = (
    "InvalidRequest",
    f"Too many configurations submitted. The maximum number of configurations is {_MAX_CONFIGS}",
)

_BUCKET_PREFIX = "sim2real-behav-"
_QUEUE_PREFIX = "sim2real-behav-q-"


def _error(fn):
    """Return the ClientError (Code, Message) of fn(); raise AssertionError when fn() succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name(_BUCKET_PREFIX)
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=name):
            objs = [
                {"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])
            ]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    try:
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _queue_configs(queue_arn: str, count: int) -> list:
    """``count`` distinct QueueConfiguration entries on the same queue, each its own key prefix."""
    return [
        {
            "Id": f"cfg{i}",
            "QueueArn": queue_arn,
            "Events": ["s3:ObjectCreated:*"],
            "Filter": {"Key": {"FilterRules": [{"Name": "prefix", "Value": f"p{i}/"}]}},
        }
        for i in range(count)
    ]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutBucketNotificationConfiguration accepts exactly 100 configurations, the fixed
    non-adjustable per-bucket cap, and rejects a 101st without replacing the stored set.
    """
    s3 = ctx.client("s3")
    sqs = ctx.client("sqs")
    bucket = _create_bucket(ctx)

    queue_url = sqs.create_queue(QueueName=ctx.unique_name(_QUEUE_PREFIX))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=queue_url))
    queue_arn = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]
    queue_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "s3.amazonaws.com"},
            "Action": "sqs:SendMessage",
            "Resource": queue_arn,
            "Condition": {"ArnEquals": {"aws:SourceArn": f"arn:aws:s3:::{bucket}"}},
        }],
    })
    sqs.set_queue_attributes(QueueUrl=queue_url, Attributes={"Policy": queue_policy})

    at_cap = _queue_configs(queue_arn, _MAX_CONFIGS)
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"QueueConfigurations": at_cap}
    )
    ctx.on_cleanup(lambda: s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={}
    ))
    stored = s3.get_bucket_notification_configuration(Bucket=bucket).get("QueueConfigurations", [])
    assert len(stored) == _MAX_CONFIGS, (
        f"{_MAX_CONFIGS} configurations, the documented cap, did not round-trip: got {len(stored)}"
    )

    over_cap = _queue_configs(queue_arn, _MAX_CONFIGS + 1)
    got = _error(lambda: s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"QueueConfigurations": over_cap}
    ))
    assert got == _TOO_MANY_CONFIGS, f"expected {_TOO_MANY_CONFIGS!r} for 101 configurations, got {got!r}"

    survived = s3.get_bucket_notification_configuration(Bucket=bucket).get("QueueConfigurations", [])
    assert len(survived) == _MAX_CONFIGS, (
        f"the rejected 101-configuration write must not have mutated the stored set, got {len(survived)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

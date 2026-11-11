"""firehose-s3-destination-wrong-bucket-arn-rejected."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-s3-destination-wrong-bucket-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "concern:eventing",
    "concern:negative-classes",
    "dp:api",
    "plane:control", "plane:data", "timing:real-time",
)
def run(ctx) -> None:
    """UpdateDestination rejects a BucketARN for a non-existent bucket with InvalidArgumentException;
    the stream's VersionId and destination are unchanged and it keeps delivering to the original
    bucket."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_good = _create_bucket(ctx, "sim2real-fh-wrongarn-")
    log_group = _create_log_group(ctx, "sim2real-fh-wrongarn-")
    role_arn = _create_role(
        ctx,
        [
            _s3_write_statement(bucket_good),
            _logs_write_statement(ctx, account_id, log_group),
        ],
    )

    stream_name = ctx.unique_name("sim2real-fh-wrongarn-")
    config = {
        "BucketARN": f"arn:aws:s3:::{bucket_good}",
        "RoleARN": role_arn,
        "Prefix": "data/",
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CloudWatchLoggingOptions": {
            "Enabled": True,
            "LogGroupName": log_group,
            "LogStreamName": "DestinationDelivery",
        },
    }
    firehose = _create_delivery_stream(ctx, stream_name, config)

    firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": b"before-update-marker\n"}
    )
    _poll_until(
        lambda: _list_keys(ctx, bucket_good, prefix="data/"),
        lambda ks: len(ks) > 0,
        timeout_s=180.0,
        interval_s=5.0,
    )

    desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"
    ]
    destination_id = desc["Destinations"][0]["DestinationId"]
    version_id = desc["VersionId"]

    nonexistent_bucket = ctx.unique_name("sim2real-fh-nonexistent-")
    try:
        firehose.update_destination(
            DeliveryStreamName=stream_name,
            CurrentDeliveryStreamVersionId=version_id,
            DestinationId=destination_id,
            ExtendedS3DestinationUpdate={
                "BucketARN": f"arn:aws:s3:::{nonexistent_bucket}",
                "RoleARN": role_arn,
                "Prefix": "data/",
                "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                "CloudWatchLoggingOptions": {
                    "Enabled": True,
                    "LogGroupName": log_group,
                    "LogStreamName": "DestinationDelivery",
                },
            },
        )
        raise AssertionError(
            "update_destination unexpectedly accepted a non-existent bucket ARN"
        )
    except ClientError as e:
        assert e.response["Error"]["Code"] == "InvalidArgumentException", (
            f"expected InvalidArgumentException for a non-existent bucket, got {e.response['Error']['Code']!r}"
        )
        expected_message = f"S3 Bucket {nonexistent_bucket} does not exist."
        assert e.response["Error"]["Message"] == expected_message, (
            f"expected the message {expected_message!r}, got {e.response['Error']['Message']!r}"
        )

    # The effect is absent: the destination configuration is unchanged (version_id
    # did not advance) and it still points at the original bucket.
    desc_after = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"
    ]
    assert desc_after["VersionId"] == version_id, (
        "delivery stream version advanced despite the rejected UpdateDestination call"
    )
    still_bucket_arn = desc_after["Destinations"][0][
        "ExtendedS3DestinationDescription"
    ]["BucketARN"]
    assert still_bucket_arn == f"arn:aws:s3:::{bucket_good}", (
        f"destination BucketARN changed to {still_bucket_arn!r} despite the rejected update"
    )

    # Positive control: delivery to the original (untouched) bucket keeps working.
    firehose.put_record(
        DeliveryStreamName=stream_name,
        Record={"Data": b"after-rejected-update-marker\n"},
    )

    def probe() -> bytes:
        return b"".join(
            _get_bytes(ctx, bucket_good, k)
            for k in _list_keys(ctx, bucket_good, prefix="data/")
        )

    content = _poll_until(
        probe,
        lambda c: b"after-rejected-update-marker" in c,
        timeout_s=180.0,
        interval_s=6.0,
    )
    assert b"after-rejected-update-marker" in content, (
        "delivery to the original bucket stopped working after the rejected update attempt"
    )


from botocore.exceptions import ClientError  # noqa: E402

_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        _empty_bucket(ctx, name)
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = page.get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )


def _s3_write_statement(bucket: str) -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": [
            "s3:AbortMultipartUpload",
            "s3:GetBucketLocation",
            "s3:GetObject",
            "s3:ListBucket",
            "s3:ListBucketMultipartUploads",
            "s3:PutObject",
        ],
        "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
    }


def _logs_write_statement(ctx, account_id: str, log_group: str) -> dict[str, Any]:
    return {
        "Effect": "Allow",
        "Action": ["logs:PutLogEvents"],
        "Resource": f"arn:aws:logs:{ctx.region}:{account_id}:log-group:{log_group}:*",
    }


def _create_log_group(ctx, prefix: str) -> str:
    logs = ctx.client("logs")
    name = ctx.unique_name(prefix)
    logs.create_log_group(logGroupName=name, tags={"sim2real": CHECK})
    logs.create_log_stream(logGroupName=name, logStreamName="DestinationDelivery")

    def _cleanup() -> None:
        try:
            logs.delete_log_group(logGroupName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _find_error_code(ctx, log_group: str, log_stream: str) -> str | None:
    logs = ctx.client("logs")
    try:
        resp = logs.get_log_events(
            logGroupName=log_group, logStreamName=log_stream, startFromHead=True
        )
    except ClientError:
        return None
    for event in resp.get("events", []):
        try:
            payload = json.loads(event["message"])
        except (ValueError, TypeError):
            continue
        code = payload.get("errorCode")
        if code:
            return code
    return None


def _create_role(ctx, policy_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_FIREHOSE),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": policy_statements}
        ),
    )

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=name, PolicyName="access")
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _wait_stream_active(
    firehose, name: str, timeout_s: float = 120.0
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        if desc["DeliveryStreamStatus"] == "ACTIVE":
            return desc
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never became ACTIVE")


def _delete_stream(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_delivery_stream(
    ctx, name: str, s3_config: dict[str, Any], timeout_s: float = 150.0
):
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=s3_config,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                time.sleep(5)
                continue
            raise
    else:
        raise AssertionError(f"create_delivery_stream never succeeded: {last_err}")
    ctx.on_cleanup(lambda: _delete_stream(firehose, name))
    _wait_stream_active(firehose, name)
    return firehose


def _list_keys(ctx, bucket: str, prefix: str = "") -> list[str]:
    s3 = ctx.client("s3")
    keys: list[str] = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket, Prefix=prefix):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


def _get_bytes(ctx, bucket: str, key: str) -> bytes:
    s3 = ctx.client("s3")
    return s3.get_object(Bucket=bucket, Key=key)["Body"].read()


def _poll_until(probe, predicate, *, timeout_s: float = 180.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""firehose-role-missing-s3-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-role-missing-s3-permission-denied"
GROUP = "overly-permissive"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Firehose stream whose role grants no S3 access writes nothing to the bucket and logs S3.AccessDenied,
    while a sibling stream with a scoped role delivers; granting the permission makes the stream deliver."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket = _create_bucket(ctx, "sim2real-fh-noperm-")

    # --- broken stream: role has ONLY logs:PutLogEvents, no s3:* at all ---
    broken_log_group = _create_log_group(ctx, "sim2real-fh-noperm-broken-")
    broken_role_arn = _create_role(
        ctx, [_logs_write_statement(ctx, account_id, broken_log_group)]
    )
    broken_stream = ctx.unique_name("sim2real-fh-noperm-broken-")
    broken_config = {
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "RoleARN": broken_role_arn,
        "Prefix": "data/",
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CloudWatchLoggingOptions": {
            "Enabled": True,
            "LogGroupName": broken_log_group,
            "LogStreamName": "DestinationDelivery",
        },
    }
    broken_firehose = _create_delivery_stream(ctx, broken_stream, broken_config)
    broken_firehose.put_record(DeliveryStreamName=broken_stream, Record={"Data": b"denied-record\n"})

    # --- positive control: role has both s3 write and logs write, same bucket, diff prefix ---
    good_log_group = _create_log_group(ctx, "sim2real-fh-noperm-good-")
    good_role_arn = _create_role(
        ctx,
        [_s3_write_statement(bucket), _logs_write_statement(ctx, account_id, good_log_group)],
    )
    good_stream = ctx.unique_name("sim2real-fh-noperm-good-")
    good_config = {
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "RoleARN": good_role_arn,
        "Prefix": "good/",
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CloudWatchLoggingOptions": {
            "Enabled": True,
            "LogGroupName": good_log_group,
            "LogStreamName": "DestinationDelivery",
        },
    }
    good_firehose = _create_delivery_stream(ctx, good_stream, good_config)
    good_firehose.put_record(DeliveryStreamName=good_stream, Record={"Data": b"control-record\n"})

    # Positive control succeeds: object appears under good/. Allow generous time for
    # IAM role permission propagation to firehose.amazonaws.com (the role was just
    # created) plus the buffering interval before the internal delivery retry lands.
    good_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, prefix="good/"),
        lambda ks: len(ks) > 0,
        timeout_s=300.0,
        interval_s=6.0,
    )
    assert good_keys, "positive-control stream with a properly-scoped role failed to deliver"

    # Broken stream logs the specific S3.AccessDenied error code.
    logged = _poll_until(
        lambda: _find_error_code(ctx, broken_log_group, "DestinationDelivery"),
        lambda code: code is not None,
        timeout_s=180.0,
        interval_s=6.0,
    )
    assert logged == "S3.AccessDenied", f"expected S3.AccessDenied, got {logged!r}"

    # The effect is absent: no object was ever written under data/ in the broken stream.
    assert _list_keys(ctx, bucket, prefix="data/") == [], (
        "records were delivered to S3 despite the role having no s3:PutObject permission"
    )

    # Restore: grant the missing s3 write permission on the SAME role/stream and confirm
    # the identical put_record call now succeeds end to end, proving the earlier denial was
    # permission-specific and not a wedged stream or a stub that always denies.
    iam = ctx.client("iam")
    broken_role_name = broken_role_arn.rsplit("/", 1)[-1]
    iam.put_role_policy(
        RoleName=broken_role_name,
        PolicyName="access",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [_s3_write_statement(bucket), _logs_write_statement(ctx, account_id, broken_log_group)],
        }),
    )
    broken_firehose.put_record(DeliveryStreamName=broken_stream, Record={"Data": b"restored-record\n"})
    restored_keys = _poll_until(
        lambda: _list_keys(ctx, bucket, prefix="data/"),
        lambda ks: len(ks) > 0,
        timeout_s=150.0,
        interval_s=6.0,
    )
    assert restored_keys, (
        "granting the missing s3:PutObject permission on the SAME role did not unblock delivery"
    )


from botocore.exceptions import ClientError  # noqa: E402

_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        # S3's CreateBucket rejects an explicit LocationConstraint of "us-east-1" (its own
        # implicit default) -- not a region default assumed by this check.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

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
            s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})


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
    logs.create_log_group(logGroupName=name)
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
        resp = logs.get_log_events(logGroupName=log_group, logStreamName=log_stream, startFromHead=True)
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
    role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST_FIREHOSE))["Role"]
    iam.put_role_policy(
        RoleName=name,
        PolicyName="access",
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
    )

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=name, PolicyName="access")
        iam.delete_role(RoleName=name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _wait_stream_active(firehose, name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
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


def _create_delivery_stream(ctx, name: str, s3_config: dict[str, Any], timeout_s: float = 150.0):
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=s3_config,
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

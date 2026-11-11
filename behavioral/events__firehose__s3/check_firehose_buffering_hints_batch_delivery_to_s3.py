"""firehose-buffering-hints-batch-delivery-to-s3."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-buffering-hints-batch-delivery-to-s3"
GROUP = "delivery"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Records sent well under the SizeInMBs buffering hint threshold in a single
    burst still land as one batched S3 object (not one object per record), proving
    the buffer accumulates records rather than delivering them individually."""
    bucket = _create_bucket(ctx)
    log_group = _create_log_group(ctx, "sim2real-fh-buf-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    role_arn = _create_role(
        ctx, [_s3_write_statement(bucket), _logs_write_statement(ctx, account_id, log_group)]
    )
    stream_name = ctx.unique_name("sim2real-fh-buf-")
    s3_config = {
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "RoleARN": role_arn,
        "Prefix": "records/",
        # SizeInMBs=1 is far larger than this burst, so delivery is driven entirely
        # by the (short) IntervalInSeconds flush -- avoiding the size-threshold
        # split-flush edge case where a partial remainder waits on its own timer.
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        "CloudWatchLoggingOptions": {
            "Enabled": True,
            "LogGroupName": log_group,
            "LogStreamName": "DestinationDelivery",
        },
    }
    firehose = _create_delivery_stream(ctx, stream_name, s3_config)

    record_count = 60
    record_bytes = [
        (json.dumps({"i": i, "pad": "x" * 40}) + "\n").encode("utf-8")
        for i in range(record_count)
    ]
    # A single burst, comfortably under the 1 MiB buffering hint (a few KB total).
    resp = firehose.put_record_batch(
        DeliveryStreamName=stream_name, Records=[{"Data": d} for d in record_bytes]
    )
    assert resp["FailedPutCount"] == 0, (
        f"expected all {record_count} records accepted, got FailedPutCount={resp['FailedPutCount']}"
    )

    def probe() -> dict[str, Any]:
        keys = _list_keys(ctx, bucket, prefix="records/")
        total_lines = sum(_get_bytes(ctx, bucket, k).count(b"\n") for k in keys)
        return {"keys": keys, "total_lines": total_lines}

    try:
        result = _poll_until(
            probe, lambda r: r["total_lines"] >= record_count, timeout_s=240.0, interval_s=6.0
        )
    except AssertionError:
        code = _find_error_code(ctx, log_group, "DestinationDelivery")
        raise AssertionError(f"records never fully delivered; delivery error code={code!r}")
    assert result["total_lines"] == record_count, (
        f"expected exactly {record_count} delivered records, got {result['total_lines']}"
    )
    # The fidelity signal: a faithful buffering implementation batches the whole
    # sub-threshold burst into a single (or a couple of) S3 object(s), never one
    # object per record.
    assert len(result["keys"]) < 5, (
        f"expected batched delivery (few objects), got {len(result['keys'])} objects "
        f"for {record_count} records"
    )


from botocore.exceptions import ClientError  # noqa: E402

_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-buf-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
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
                # Newly-created IAM role not yet visible/propagated to Firehose.
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

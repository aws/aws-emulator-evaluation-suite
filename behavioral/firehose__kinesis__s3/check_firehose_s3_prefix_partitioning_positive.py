"""firehose-s3-prefix-partitioning-positive."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "firehose-s3-prefix-partitioning-positive"
GROUP = "data-format"
SERVICES = ["firehose", "kinesis", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Firehose S3 destination's custom Prefix template (using the timestamp namespace) is
    evaluated at delivery time into the expected time-partitioned S3 key structure."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")

    bucket, bucket_arn = _create_bucket(ctx)
    role_arn = _create_role(ctx, [_s3_write_statement(bucket_arn)], "pfx")

    prefix_template = "sim2real-data/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
    error_prefix_template = "sim2real-errors/!{firehose:error-output-type}/"

    delivery_name = ctx.unique_name("sim2real-fh-")
    before = datetime.now(timezone.utc)
    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        delivery_name,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": bucket_arn,
            "Prefix": prefix_template,
            "ErrorOutputPrefix": error_prefix_template,
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 0},
        },
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    _wait_delivery_stream_active(firehose, delivery_name)

    marker = ctx.unique_name("marker-")
    firehose.put_record(DeliveryStreamName=delivery_name, Record={"Data": f"payload-{marker}".encode()})

    # The prefix is evaluated from the arrival timestamp of the oldest record in the object
    # (UTC by default); bound the expected date range across the put -> now.
    after = datetime.now(timezone.utc)
    expected_prefixes = _candidate_prefixes(before, after)

    objects: list[dict[str, Any]] = []
    matched_prefix = None
    left = ctx.time_left()
    deadline = time.monotonic() + (240 if left is None else max(1.0, min(240, left - 5.0)))
    while time.monotonic() < deadline and not objects:
        for candidate in expected_prefixes:
            found = _list_objects(s3, bucket, prefix=candidate)
            if found:
                objects = found
                matched_prefix = candidate
                break
        if not objects:
            time.sleep(2)
    assert objects, f"no object appeared under any of the expected prefixes {expected_prefixes}"

    key = objects[0]["Key"]
    assert key.startswith(matched_prefix), f"delivered key {key!r} does not start with matched date prefix {matched_prefix!r}"
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    assert marker.encode() in body, f"delivered object {key!r} body did not contain marker {marker!r}"

    # The error-output namespace is a distinct template evaluated only on a delivery failure;
    # a clean DirectPut delivery must not have produced anything under it.
    error_objects = _list_objects(s3, bucket, prefix="sim2real-errors/")
    assert not error_objects, (
        f"clean delivery should not populate the error-output prefix, found "
        f"{[o['Key'] for o in error_objects]}"
    )


# ===== helpers =====


def _candidate_prefixes(before: datetime, after: datetime) -> list[str]:
    seen: list[str] = []
    day = before
    while True:
        candidate = f"sim2real-data/year={day:%Y}/month={day:%m}/day={day:%d}/"
        if candidate not in seen:
            seen.append(candidate)
        if day >= after:
            break
        day = day.replace(hour=23, minute=59, second=59)
    return seen


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-s3-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # "us-east-1" here is not a region pin on the bucket (Bucket lives in ctx.region always) —
    # it is S3's own CreateBucket quirk: passing a LocationConstraint for the partition's default
    # region is rejected, so it is only ever supplied for every other region.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )

    def _cleanup() -> None:
        token = None
        while True:
            kw: dict[str, Any] = {"Bucket": name}
            if token:
                kw["ContinuationToken"] = token
            resp = s3.list_objects_v2(**kw)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
            if resp.get("IsTruncated"):
                token = resp.get("NextContinuationToken")
            else:
                break
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name, f"arn:aws:s3:::{name}"


def _s3_write_statement(bucket_arn: str) -> dict[str, Any]:
    resource = "*" if bucket_arn == "*" else [bucket_arn, f"{bucket_arn}/*"]
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
        "Resource": resource,
    }


def _create_role(ctx, statements: list[dict[str, Any]], suffix: str) -> str:
    iam = ctx.client("iam")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_name = ctx.unique_name(f"sim2real-fh-role-{suffix}-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "delivery-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _create_delivery_stream_with_retry(ctx, firehose, name: str, **kwargs: Any) -> None:
    deadline = time.monotonic() + 150
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, **kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream_and_wait(firehose, name))


def _delete_stream_and_wait(firehose, name: str, timeout_s: float = 300.0) -> None:
    """Delete the stream and poll every 2 s until it is gone: DeleteDeliveryStream returns while
    the stream is still DELETING, and a still-listed stream is a leak. Raises at the deadline."""
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"delivery stream {name} still present {timeout_s}s after DeleteDeliveryStream")
        time.sleep(2)


def _wait_delivery_stream_active(firehose, name: str, timeout_s: float = 180.0) -> None:
    status = _poll_until(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
            "DeliveryStreamStatus"
        ],
        lambda s: s in ("ACTIVE", "CREATING_FAILED"),
        timeout_s=timeout_s,
        interval_s=5,
    )
    if status != "ACTIVE":
        raise AssertionError(f"delivery stream {name} failed to activate: {status}")


def _list_objects(s3, bucket: str, prefix: str = "") -> list[dict[str, Any]]:
    resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    return resp.get("Contents", [])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""firehose-s3-prefix-partitioning."""
from __future__ import annotations

import datetime
import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-s3-prefix-partitioning"
GROUP = "delivery"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A custom Prefix template with !{timestamp:...} expressions is evaluated into
    a real date-partitioned S3 key, and well-formed records never land under the
    (unused) ErrorOutputPrefix location."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, [_s3_write_statement(bucket)])
    stream_name = ctx.unique_name("sim2real-fh-prefix-")
    s3_config = {
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "RoleARN": role_arn,
        "Prefix": "data/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/",
        "ErrorOutputPrefix": (
            "errors/!{firehose:error-output-type}/"
            "year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/"
        ),
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
    }
    firehose = _create_delivery_stream(ctx, stream_name, s3_config)

    send_time = datetime.datetime.now(datetime.timezone.utc)
    records = [json.dumps({"i": i}).encode("utf-8") + b"\n" for i in range(10)]
    resp = firehose.put_record_batch(
        DeliveryStreamName=stream_name, Records=[{"Data": d} for d in records]
    )
    assert resp["FailedPutCount"] == 0, (
        f"expected all {len(records)} records accepted, got FailedPutCount={resp['FailedPutCount']}"
    )

    expected_prefix = f"data/year={send_time:%Y}/month={send_time:%m}/day={send_time:%d}/"

    result = _poll_until(
        lambda: _list_keys(ctx, bucket, prefix="data/"),
        lambda keys: len(keys) > 0,
        timeout_s=180.0,
        interval_s=5.0,
    )
    for key in result:
        assert key.startswith(expected_prefix), (
            f"delivered key {key!r} does not start with expected date prefix {expected_prefix!r}"
        )

    error_keys = _list_keys(ctx, bucket, prefix="errors/")
    assert error_keys == [], f"well-formed records unexpectedly landed under errors/: {error_keys}"


from botocore.exceptions import ClientError  # noqa: E402

_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-prefix-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # us-east-1 is the one region where CreateBucket rejects an explicit LocationConstraint;
    # this is an S3 API quirk, not an assumption about which region the check runs in.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

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


def _create_role(ctx, policy_statements: list[dict[str, Any]]) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-fh-role-")
    role = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(_TRUST_FIREHOSE),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]
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
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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

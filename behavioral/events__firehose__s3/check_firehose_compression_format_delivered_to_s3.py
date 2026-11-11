"""firehose-compression-format-delivered-to-s3."""
from __future__ import annotations

import gzip
import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-compression-format-delivered-to-s3"
GROUP = "data-format"
SERVICES = ["events", "firehose", "s3"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """CompressionFormat=GZIP on the S3 destination means the delivered object is a
    real gzip stream whose decompressed bytes reproduce every sent record exactly."""
    bucket = _create_bucket(ctx)
    role_arn = _create_role(ctx, [_s3_write_statement(bucket)])
    stream_name = ctx.unique_name("sim2real-fh-gzip-")
    s3_config = {
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "RoleARN": role_arn,
        "Prefix": "data/",
        "CompressionFormat": "GZIP",
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
    }
    firehose = _create_delivery_stream(ctx, stream_name, s3_config)

    sent_lines = [json.dumps({"i": i, "marker": "sim2real-gzip"}) for i in range(5)]
    resp = firehose.put_record_batch(
        DeliveryStreamName=stream_name,
        Records=[{"Data": (line + "\n").encode("utf-8")} for line in sent_lines],
    )
    assert resp["FailedPutCount"] == 0, (
        f"PutRecordBatch of {len(sent_lines)} records reported failures: {resp!r}"
    )

    keys = _poll_until(
        lambda: _list_keys(ctx, bucket, prefix="data/"),
        lambda ks: len(ks) > 0,
        timeout_s=180.0,
        interval_s=5.0,
    )

    # A single PutRecordBatch call is one producer call, so Firehose's ordering guarantee
    # applies: the delivered bytes reproduce this batch in the order it was put. (Firehose
    # makes no ordering promise ACROSS separate producer calls, so this would not hold for
    # multiple put_record_batch/put_record calls.)
    all_decompressed_lines: list[str] = []
    for key in keys:
        raw = _get_bytes(ctx, bucket, key)
        assert raw[:2] == b"\x1f\x8b", f"object {key!r} is not gzip-magic prefixed: {raw[:16]!r}"
        text = gzip.decompress(raw).decode("utf-8")
        all_decompressed_lines.extend(line for line in text.splitlines() if line.strip())

    assert all_decompressed_lines == sent_lines, (
        f"decompressed delivered content {all_decompressed_lines} != sent (in order) {sent_lines}"
    )


from botocore.exceptions import ClientError  # noqa: E402

_TRUST_FIREHOSE = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-gzip-")
    kwargs: dict[str, Any] = {"Bucket": name}
    # LocationConstraint must be omitted for us-east-1 specifically (CreateBucket rejects it
    # there); this is the API's own region quirk, not a region pin on the check's resource.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _MANAGED_TAGS})

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
        Tags=_MANAGED_TAGS,
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
                Tags=_MANAGED_TAGS,
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

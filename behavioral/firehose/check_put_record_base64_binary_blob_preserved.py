"""put-record-base64-binary-blob-preserved."""
from __future__ import annotations

import json
import os
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-base64-binary-blob-preserved"
GROUP = "state-machine"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Raw non-UTF8 binary bytes survive PutRecord + S3 delivery unchanged (Data is opaque)."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    prefix = "binary-test/"
    stream_name = _create_s3_delivery_stream(
        ctx, role_arn, bucket, prefix, buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 0}
    )

    # Every byte value 0x00-0xFF plus random bytes: guaranteed to contain invalid UTF-8
    # sequences, so a transport that silently treats Data as text would corrupt it.
    payload = bytes(range(256)) + os.urandom(4096) + bytes(range(255, -1, -1))

    firehose = ctx.client("firehose")
    resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})
    assert resp["RecordId"], f"expected a non-empty RecordId, got {resp!r}"

    delivered = _wait_for_s3_bytes(ctx, bucket, prefix, timeout_s=_budget_s(ctx, 240.0))
    assert len(delivered) == len(payload), (
        f"expected {len(payload)} delivered bytes, got {len(delivered)}"
    )
    assert delivered == payload, "delivered S3 bytes differ from the original raw binary payload"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]})

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_s3_delivery_stream(ctx, role_arn: str, bucket: str, prefix: str, buffering_hints=None) -> str:
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-stream-")
    hints = buffering_hints or {"SizeInMBs": 1, "IntervalInSeconds": 60}
    config = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": prefix,
        "BufferingHints": hints,
        "CompressionFormat": "UNCOMPRESSED",
    }
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    created = False
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            created = True
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                last_err = e
                time.sleep(2)
                continue
            raise
    if not created:
        raise AssertionError(f"delivery stream never created (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
    _wait_for_stream_active(ctx, name, timeout_s=_budget_s(ctx, 120.0))
    return name


def _wait_for_stream_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"delivery stream {name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"delivery stream {name} never became ACTIVE within {timeout_s}s")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for_s3_bytes(ctx, bucket: str, prefix: str, timeout_s: float = 240.0, interval_s: float = 1.0) -> bytes:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        contents = resp.get("Contents", [])
        if contents:
            keys = sorted(o["Key"] for o in contents)
            data = b"".join(s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in keys)
            return data
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"an object delivered to s3://{bucket}/{prefix}: the run budget ended first; not graded")
    raise AssertionError(f"no object ever delivered to s3://{bucket}/{prefix} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

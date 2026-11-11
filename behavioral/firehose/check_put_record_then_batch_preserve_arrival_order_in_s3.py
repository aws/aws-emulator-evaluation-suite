"""put-record-then-batch-preserve-arrival-order-in-s3."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "put-record-then-batch-preserve-arrival-order-in-s3"
GROUP = "ordering"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A sequential PutRecord followed immediately by a PutRecordBatch, both landing in the
    same buffered flush to a single S3 destination, deliver every record exactly once.
    """
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    name = ctx.unique_name("sim2real-behav-frh-")
    # Large size hint + short interval hint => the flush is purely time-triggered, so every
    # record sent within the interval lands together in one flush.
    _create_s3_stream_with_retry(
        ctx, name, bucket, role_arn,
        buffering_hints={"SizeInMBs": 128, "IntervalInSeconds": 60},
    )
    _wait_stream_active(ctx, name)

    firehose = ctx.client("firehose")
    expected = ["solo-0000"]
    firehose.put_record(DeliveryStreamName=name, Record={"Data": b"solo-0000\n"})
    batch_records = []
    for i in range(1, 6):
        tag = f"batch-{i:04d}"
        expected.append(tag)
        batch_records.append({"Data": f"{tag}\n".encode()})
    resp = firehose.put_record_batch(DeliveryStreamName=name, Records=batch_records)
    assert resp["FailedPutCount"] == 0, f"unexpected per-record failures: {resp['RequestResponses']}"

    objs = _poll_s3_objects(ctx, bucket, min_count=1, timeout_s=200.0)
    assert objs, "no object was ever delivered to S3"
    content = _concat_objects(ctx, bucket, objs)
    lines = [ln for ln in content.split("\n") if ln]
    # Firehose does not keep records in order, so the records are compared as a multiset.
    assert sorted(lines) == sorted(expected), (
        f"expected each of {expected} delivered exactly once, got {lines}"
    )


# ===== helpers =====

def _safe(fn, *missing: str) -> None:
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in missing:
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-frh-")
    # us-east-1 is the sole region that rejects CreateBucket if LocationConstraint is set.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(lambda: _safe(_cleanup, "NoSuchBucket"))
    return bucket


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-frh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_name = f"{role_name}-policy"
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"))
    return role_arn


def _create_s3_stream_with_retry(
    ctx, name: str, bucket: str, role_arn: str,
    buffering_hints: dict[str, Any] | None = None,
    compression: str | None = None,
    timeout_s: float = 90.0,
) -> None:
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    s3_config: dict[str, Any] = {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"}
    if buffering_hints:
        s3_config["BufferingHints"] = buffering_hints
    if compression:
        s3_config["CompressionFormat"] = compression
    ctx.on_cleanup(lambda: _safe(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True),
        "ResourceNotFoundException",
    ))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            role_not_ready = "not authorized" in msg or "unable to assume role" in msg
            if code == "InvalidArgumentException" and role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_stream_active(ctx, name: str, timeout_s: float = 120.0) -> dict[str, Any]:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"delivery stream {name} entered {status}")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


def _poll_s3_objects(ctx, bucket: str, prefix: str = "", min_count: int = 1,
                      timeout_s: float = 180.0, interval_s: float = 5.0) -> list[dict[str, Any]]:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    objs: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        objs = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
        if len(objs) >= min_count:
            break
        time.sleep(interval_s)
    return sorted(objs, key=lambda o: o["LastModified"])


def _concat_objects(ctx, bucket: str, objs: list[dict[str, Any]]) -> str:
    s3 = ctx.client("s3")
    parts = []
    for o in objs:
        body = s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read()
        parts.append(body.decode("utf-8"))
    return "".join(parts)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""buffering-size-threshold-triggers-early-flush."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "buffering-size-threshold-triggers-early-flush"
GROUP = "visibility-timeout-ttl"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Reaching the configured BufferingHints.SizeInMBs threshold flushes buffered records to
    S3 well before the (much longer) IntervalInSeconds timeout would have elapsed."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    name = ctx.unique_name("sim2real-behav-frh-")
    interval_s = 900  # max allowed -- if this test observes delivery, it was size-triggered
    size_mb = 1  # min allowed -- easy to exceed with a handful of ~230KB records
    _create_s3_stream_with_retry(
        ctx, name, bucket, role_arn,
        buffering_hints={"SizeInMBs": size_mb, "IntervalInSeconds": interval_s},
    )
    _wait_stream_active(ctx, name)

    marker = ctx.unique_name("szflush-")
    firehose = ctx.client("firehose")
    record_count = 5
    payload_each = 230 * 1024  # ~230 KiB per record; 5x => ~1.15 MiB > 1 MiB threshold
    records = []
    for i in range(record_count):
        prefix = f"{marker}-{i:02d}-".encode()
        records.append({"Data": prefix + b"A" * (payload_each - len(prefix))})
    start = time.monotonic()
    resp = firehose.put_record_batch(DeliveryStreamName=name, Records=records)
    assert resp["FailedPutCount"] == 0, (
        f"expected 0 failed puts for {record_count} records, got {resp['FailedPutCount']}: "
        f"{resp['RequestResponses']}"
    )

    # Time semantic: the poll budget (420s) is under half the 900s interval, so an object
    # that appears inside it can only come from the size trigger. The budget is generous
    # because S3 delivery latency on a fresh role/stream can run into a few minutes even
    # when the size threshold is hit at once.
    objs = _poll_s3_objects(ctx, bucket, min_count=1, timeout_s=420.0)
    elapsed = time.monotonic() - start
    assert objs, f"record batch was never flushed to S3 within {elapsed:.0f}s (size threshold not honored)"
    assert elapsed < interval_s, f"flush took {elapsed:.0f}s, not earlier than the {interval_s}s interval"

    content = _concat_objects(ctx, bucket, objs)
    occurrences = content.count(marker)
    assert occurrences == record_count, (
        f"expected all {record_count} records for marker {marker!r} in the early flush, found {occurrences}"
    )


# ===== helpers =====

def _safe(fn, *missing: str) -> None:
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in missing:
            raise


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-frh-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )

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
                      timeout_s: float = 180.0, poll_s: float = 2.0) -> list[dict[str, Any]]:
    s3 = ctx.client("s3")
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else max(1.0, min(timeout_s, left - 5.0)))
    objs: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        objs = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
        if len(objs) >= min_count:
            break
        time.sleep(poll_s)
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

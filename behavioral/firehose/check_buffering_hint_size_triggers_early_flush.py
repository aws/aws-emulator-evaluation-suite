"""buffering-hint-size-triggers-early-flush."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "buffering-hint-size-triggers-early-flush"
GROUP = "visibility-timeout-ttl"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Exceeding the BufferingHints SizeInMBs threshold delivers to S3 well before the 900 s
    interval timer, and an earlier below-threshold record lands in that same object (no per-record flush)."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, f"arn:aws:s3:::{bucket}")
    stream_name = ctx.unique_name("sim2real-behav-fh-")
    # IntervalInSeconds pinned to its max (900) so the interval timer alone could not
    # plausibly explain an early flush; SizeInMBs pinned to its min (1) so a single
    # batch that clears 1 MiB should trigger delivery on its own
    # (https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html).
    _create_delivery_stream_s3(
        ctx, stream_name, role_arn, f"arn:aws:s3:::{bucket}",
        {"IntervalInSeconds": 900, "SizeInMBs": 1},
    )
    ctx.on_cleanup(lambda: _delete_stream(ctx, stream_name))
    _wait_stream_active(ctx, stream_name)

    fh = ctx.client("firehose")

    # Contrast control: a single record is nowhere near the 1 MiB hint, so it must stay buffered
    # and arrive in the same object as the size-triggered batch, not in an object of its own.
    resp0 = fh.put_record(DeliveryStreamName=stream_name, Record={"Data": b"below-threshold\n"})
    assert resp0.get("RecordId"), f"below-threshold record was not accepted: {resp0}"

    chunk = ("y" * 4000).encode()
    records = [{"Data": chunk} for _ in range(500)]  # ~1.9 MiB, comfortably over the 1 MiB hint
    resp = fh.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, f"expected 0 failed puts, got {resp['FailedPutCount']}"

    # BufferingHints are hints with no documented delivery latency; a 420 s wait stays well under
    # the 900 s interval, so only a size-triggered flush can land inside it.
    wait_s = 420.0
    budget_s = _budget_s(ctx, wait_s)
    objects = _poll_until(
        lambda: _list_objects(ctx, bucket),
        lambda objs: len(objs) > 0,
        timeout_s=min(wait_s, budget_s),
        interval_s=2.0,
    )
    if not objects and budget_s < wait_s:
        raise TimeoutError(
            f"the check's time budget ran out after {budget_s:.0f}s, before the {wait_s:.0f}s "
            "delivery wait ended; not graded"
        )
    assert objects, f"no object delivered within {wait_s:.0f}s despite exceeding the size hint"

    s3 = ctx.client("s3")
    bodies = {o["Key"]: s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read() for o in objects}
    holder = [k for k, body in bodies.items() if b"below-threshold" in body]
    assert holder, f"below-threshold record missing from the delivered objects {sorted(bodies)}"
    assert chunk in bodies[holder[0]], (
        f"below-threshold record was flushed on its own in {holder[0]} "
        f"({len(bodies[holder[0]])} bytes) instead of with the size-triggered batch"
    )


# ===== helpers =====

def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-fh-").lower()
    if ctx.region == "us-east-1":
        # CreateBucketConfiguration.LocationConstraint must be omitted for us-east-1 --
        # S3 rejects the call if it is set to the bucket's own default region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]}
    )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_firehose_role(ctx, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
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
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="s3-access", PolicyDocument=json.dumps(policy_doc))
    return role["Arn"]


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_delivery_stream_s3(ctx, name: str, role_arn: str, bucket_arn: str, buffering_hints: dict) -> None:
    fh = ctx.client("firehose")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": bucket_arn,
                    "BufferingHints": buffering_hints,
                },
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _delete_stream(ctx, name: str) -> None:
    fh = ctx.client("firehose")
    try:
        fh.delete_delivery_stream(DeliveryStreamName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(ctx, name: str, timeout: float = 180.0) -> dict:
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream entered CREATING_FAILED: {desc.get('FailureDescription')}")
        time.sleep(3.0)
    raise AssertionError("delivery stream did not become ACTIVE in time")


def _list_objects(ctx, bucket: str) -> list:
    s3 = ctx.client("s3")
    return s3.list_objects_v2(Bucket=bucket).get("Contents", [])


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, timeout_s: float = 120.0, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result if predicate(result) else None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

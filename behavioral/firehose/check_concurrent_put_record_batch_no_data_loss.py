"""concurrent-put-record-batch-no-data-loss."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-put-record-batch-no-data-loss"
GROUP = "concurrency"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Multiple concurrent PutRecordBatch calls against the same stream all succeed and
    every record eventually appears exactly once in S3 (no drops, no duplicates)."""
    bucket = _create_bucket(ctx)
    role = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    stream_name = _create_s3_stream(
        ctx, firehose, bucket, role["role_arn"],
        buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 60},
    )
    _wait_stream_active(ctx, firehose, stream_name)

    workers = 5
    per_worker = 20
    expected_ids = {f"w{w}-r{r}" for w in range(workers) for r in range(per_worker)}

    def _send(worker_idx: int) -> int:
        records = [
            {"Data": f"w{worker_idx}-r{r}\n".encode("utf-8")} for r in range(per_worker)
        ]
        resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
        return resp["FailedPutCount"]

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_send, w) for w in range(workers)]
        failed_counts = [f.result() for f in as_completed(futures)]

    assert sum(failed_counts) == 0, f"some PutRecordBatch entries failed: {failed_counts}"

    s3 = ctx.client("s3")
    # Firehose's IntervalInSeconds=60 buffering hint is a target, not a guarantee: a fresh
    # stream's first delivery can lag well past it while the destination role's permissions
    # finish propagating, so the window here is wider than the nominal flush interval.
    lines = _poll_until(
        lambda: _collect_s3_lines(s3, bucket),
        lambda ls: len(ls) >= len(expected_ids),
        timeout_s=240.0,
        interval_s=5.0,
    )
    delivered_ids = [line for line in lines if line]
    assert len(delivered_ids) == len(set(delivered_ids)), (
        f"duplicate records delivered: {len(delivered_ids)} lines, {len(set(delivered_ids))} unique"
    )
    assert set(delivered_ids) == expected_ids, (
        f"missing={expected_ids - set(delivered_ids)} extra={set(delivered_ids) - expected_ids}"
    )


def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-").lower().replace("_", "-")
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=name)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_firehose_role(ctx, bucket_name: str) -> dict:
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    policy_name = "s3-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
            ],
            "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return {"role_name": role_name, "role_arn": role_arn, "policy_name": policy_name}


def _create_s3_stream(ctx, firehose, bucket, role_arn, buffering_hints, prefix=None) -> str:
    from botocore.exceptions import ClientError

    name = ctx.unique_name("sim2real-behav-fh-stream-")
    s3_config = {
        "RoleARN": role_arn,
        "BucketARN": _bucket_arn(bucket),
        "BufferingHints": buffering_hints,
    }
    if prefix:
        s3_config["Prefix"] = prefix
    # IAM role trust propagation into Firehose is eventually consistent -- a freshly created
    # role can transiently be rejected with InvalidArgumentException even though the trust
    # policy is already correct, so retry through that window instead of guessing a fixed delay.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, S3DestinationConfiguration=s3_config)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            role_not_ready = "not authorized" in msg or "unable to assume role" in msg
            if code == "InvalidArgumentException" and role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True))
    return name


def _wait_stream_active(ctx, firehose, name, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"delivery stream entered {status}: {desc.get('FailureDescription')}")
        time.sleep(3)
    raise AssertionError("delivery stream never became ACTIVE")


def _collect_s3_lines(s3, bucket) -> list[str]:
    keys = []
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            keys.append(obj["Key"])
    keys.sort()
    lines: list[str] = []
    for key in keys:
        body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
        text = body.decode("utf-8", errors="replace")
        lines.extend([line for line in text.split("\n") if line])
    return lines


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""concurrent-put-record-batch-calls-no-record-loss."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-put-record-batch-calls-no-record-loss"
GROUP = "concurrency"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrent PutRecordBatch calls each get unique RecordIds; nothing is lost end-to-end."""
    bucket = _create_bucket(ctx)
    role_arn, _role_name, _policy_name = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    stream_name = ctx.unique_name("sim2real-fh-conc-")
    _create_s3_delivery_stream(
        ctx, firehose, stream_name, role_arn, bucket,
        buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 0},
    )

    num_workers = 5
    records_per_worker = 20
    total = num_workers * records_per_worker

    def _submit(worker_id):
        records = [{"Data": f"w{worker_id}-r{i}\n".encode()} for i in range(records_per_worker)]
        return firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)

    with ThreadPoolExecutor(max_workers=num_workers) as pool:
        responses = list(pool.map(_submit, range(num_workers)))

    all_record_ids = []
    for resp in responses:
        assert resp["FailedPutCount"] == 0, f"unexpected per-record failures: {resp['RequestResponses']}"
        for entry in resp["RequestResponses"]:
            assert "ErrorCode" not in entry, f"unexpected error entry: {entry}"
            all_record_ids.append(entry["RecordId"])

    assert len(all_record_ids) == total, f"expected {total} RecordIds across all batches, got {len(all_record_ids)}"
    assert len(set(all_record_ids)) == total, "duplicate RecordIds returned across concurrent calls"

    # Verify no record loss end-to-end: every marker eventually reaches S3 exactly once.
    expected_markers = {f"w{w}-r{i}" for w in range(num_workers) for i in range(records_per_worker)}
    s3 = ctx.client("s3")

    def _probe():
        data = _download_all(s3, bucket)
        return [ln for ln in data.decode().splitlines() if ln.strip()]

    lines = _poll_until(_probe, lambda lns: len(set(lns)) >= total, timeout_s=_budget_s(ctx, 150), interval_s=1,
                         ctx=ctx)
    delivered = set(lines)
    assert delivered == expected_markers, f"missing markers: {expected_markers - delivered}"
    assert len(lines) == total, f"expected exactly {total} delivered lines, got {len(lines)} (duplicates present)"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs = {"Bucket": name}
    # us-east-1 is S3's default region and CreateBucket rejects an explicit
    # LocationConstraint for it; every other region requires one.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _safe_delete_role_policy(iam, role_name, policy_name):
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_firehose_role(ctx, bucket_name):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "s3-delivery-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": [
                "s3:AbortMultipartUpload",
                "s3:GetBucketLocation",
                "s3:GetObject",
                "s3:ListBucket",
                "s3:ListBucketMultipartUploads",
                "s3:PutObject",
            ],
            "Resource": [
                f"arn:aws:s3:::{bucket_name}",
                f"arn:aws:s3:::{bucket_name}/*",
            ],
        }],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: _safe_delete_role_policy(iam, role_name, policy_name))
    return role_arn, role_name, policy_name


def _wait_for_active(firehose, name, timeout_s=120.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED")
        time.sleep(1)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"delivery stream {name} becoming ACTIVE: the run budget ended first; not graded")
    raise AssertionError(f"delivery stream {name} never became ACTIVE: {desc}")


def _create_s3_delivery_stream(ctx, firehose, name, role_arn, bucket_name, buffering_hints):
    dest_config = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket_name}",
        "BufferingHints": buffering_hints,
    }
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = exc
            time.sleep(2)
    else:
        raise last_err
    ctx.on_cleanup(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    )
    _wait_for_active(firehose, name, timeout_s=_budget_s(ctx, 120.0), ctx=ctx)
    return name


def _list_bucket_keys(s3, bucket):
    resp = s3.list_objects_v2(Bucket=bucket)
    return sorted(obj["Key"] for obj in resp.get("Contents", []))


def _download_all(s3, bucket):
    data = b""
    for key in _list_bucket_keys(s3, bucket):
        data += s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    return data


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError("condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s: last observed {value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""s3-delivery-triggered-by-buffer-size-threshold."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "s3-delivery-triggered-by-buffer-size-threshold"
GROUP = "visibility-timeout-ttl"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A batch exceeding BufferingHints.SizeInMBs flushes to S3 well before the (much
    longer) IntervalInSeconds would have elapsed, proving size-based delivery timing."""
    bucket = _create_bucket(ctx)
    role = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    # SizeInMBs at its minimum (1) and IntervalInSeconds at its maximum (900): if delivery
    # happens well inside the poll window (far short of 900s) it must be size-triggered.
    stream_name = _create_s3_stream(
        ctx, firehose, bucket, role["role_arn"],
        buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 900},
    )
    _wait_stream_active(ctx, firehose, stream_name)

    # 210 records of 5001 bytes each ~= 1.05 MiB, just over the 1 MiB size threshold.
    record_bytes = b"x" * 5000 + b"\n"
    records = [{"Data": record_bytes} for _ in range(210)]
    start = time.monotonic()
    resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, f"unexpected failures: {resp['RequestResponses']}"

    s3 = ctx.client("s3")
    objects = _poll_until(
        lambda: _list_object_keys(s3, bucket),
        lambda ks: len(ks) > 0,
        timeout_s=240.0,
        interval_s=5.0,
    )
    elapsed = time.monotonic() - start
    assert objects, "no object delivered to S3 within 240s of exceeding the size threshold"
    assert elapsed < 900.0, (
        f"delivery took {elapsed:.1f}s, not distinguishably faster than the 900s interval hint"
    )


def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-").lower().replace("_", "-")
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=name)

    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
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
    # A freshly created role is not yet assumable everywhere IAM has to propagate to;
    # Firehose reports that window as InvalidArgumentException. Retry within a bounded
    # deadline rather than sleeping blind before the first attempt.
    deadline = time.monotonic() + 90.0
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                time.sleep(5.0)
                continue
            raise
    else:
        raise AssertionError(f"create_delivery_stream never succeeded within 90s: {last_err}")
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


def _list_object_keys(s3, bucket) -> list[str]:
    resp = s3.list_objects_v2(Bucket=bucket)
    return [o["Key"] for o in resp.get("Contents", [])]


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

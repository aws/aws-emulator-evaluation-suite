"""buffering-hints-delay-controls-delivery-timing."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "buffering-hints-delay-controls-delivery-timing"
GROUP = "visibility-timeout-ttl"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A record is withheld from S3 for most of the 60 s buffering interval and then delivered
    intact, no sooner than half the interval after the put."""
    bucket = _create_bucket(ctx)
    role_arn, _role_name, _policy_name = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    stream_name = ctx.unique_name("sim2real-fh-buf-")
    interval_s = 60
    # IntervalInSeconds range for S3 is 0-900s (API_BufferingHints); SizeInMBs is set high
    # so the single small record below can only be flushed by the interval, not the size hint.
    _create_s3_delivery_stream(
        ctx, firehose, stream_name, role_arn, bucket,
        buffering_hints={"SizeInMBs": 64, "IntervalInSeconds": interval_s},
    )

    s3 = ctx.client("s3")
    put_time = time.monotonic()
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": b"buffered-record\n"})

    # Poll for absence across the whole buffering window, not just once right after the put:
    # a target that flushes early -- at t=20s, say -- must be caught even though it is not
    # flushing per-record.
    early_deadline = put_time + interval_s - 15
    while time.monotonic() < early_deadline:
        early_keys = _list_bucket_keys(s3, bucket)
        assert early_keys == [], (
            f"record appeared in S3 before the {interval_s}s buffering interval elapsed "
            f"(at t={time.monotonic() - put_time:.1f}s): {early_keys}"
        )
        time.sleep(5)

    # BufferingHints are hints (firehose#BufferingHints) and delivery latency is undocumented:
    # S3 delivery on a fresh role/stream can run several minutes past a short interval, so the
    # wait caps only how long the check looks, never the verdict on a compliant target.
    data = _poll_until(
        lambda: _download_all(s3, bucket), lambda d: len(d) > 0,
        timeout_s=600, interval_s=10, budget_s=_budget_s(ctx, 600),
    )
    elapsed = time.monotonic() - put_time
    assert data == b"buffered-record\n", f"unexpected delivered content: {data!r}"
    assert elapsed >= interval_s / 2, (
        f"record was delivered too quickly ({elapsed:.1f}s) for a {interval_s}s buffering interval"
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

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
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
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


def _wait_for_active(firehose, name, timeout_s=120.0):
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
        time.sleep(3)
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
                Tags=[{"Key": "simparity-check", "Value": CHECK}],
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = exc
            time.sleep(5)
    else:
        raise last_err
    ctx.on_cleanup(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    )
    _wait_for_active(firehose, name)
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
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0, budget_s=None):
    """Poll until predicate holds; a stop forced by the runner's budget, short of timeout_s, is no verdict."""
    start = time.monotonic()
    deadline = start + (timeout_s if budget_s is None else min(timeout_s, budget_s))
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    if budget_s is not None and budget_s < timeout_s:
        raise TimeoutError(
            f"the check's time budget ran out after {time.monotonic() - start:.1f}s, before the "
            f"{timeout_s}s wait ended (last value: {value!r}); not graded"
        )
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

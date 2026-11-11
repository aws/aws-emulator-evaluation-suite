"""put-record-batch-preserves-submission-order-in-s3."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-preserves-submission-order-in-s3"
GROUP = "ordering"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Records submitted in a single PutRecordBatch call land in S3 in the same order."""
    bucket = _create_bucket(ctx)
    role_arn, _role_name, _policy_name = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    stream_name = ctx.unique_name("sim2real-fh-ord-")
    _create_s3_delivery_stream(
        ctx, firehose, stream_name, role_arn, bucket,
        buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 60},
    )

    n = 100
    records = [{"Data": f"{i:04d}\n".encode()} for i in range(n)]
    resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, f"unexpected per-record failures: {resp['RequestResponses']}"

    s3 = ctx.client("s3")
    data = _poll_until(
        lambda: _download_all(s3, bucket),
        lambda d: _count_lines(d) >= n,
        timeout_s=150,
        interval_s=5,
        description=f"{n} delivered lines in s3://{bucket}",
    )

    lines = _lines(data)
    expected = [f"{i:04d}" for i in range(n)]
    assert lines == expected, f"delivered order diverged from submission order: {lines[:5]} vs {expected[:5]}"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs = {"Bucket": name}
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
    # The delivery role was just created; IAM's eventual-consistency window means Firehose
    # may reject the role as not-yet-assumable for a short period after creation.
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


def _lines(data):
    return [ln for ln in data.decode().splitlines() if ln.strip()]


def _count_lines(data):
    return len(_lines(data))


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observed: {value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

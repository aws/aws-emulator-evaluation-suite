"""put-record-batch-preserves-record-order-in-s3-object."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-preserves-record-order-in-s3-object"
GROUP = "ordering"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Every record of one PutRecordBatch call is delivered to S3 and nothing else is; delivery is
    at-least-once and unordered, so the delivered lines compare as a set."""
    bucket = _create_bucket(ctx)
    role = _create_firehose_role(ctx, bucket)
    firehose = ctx.client("firehose")
    stream_name = _create_s3_stream(
        ctx, firehose, bucket, role["role_arn"],
        buffering_hints={"SizeInMBs": 1, "IntervalInSeconds": 60},
    )
    _wait_stream_active(ctx, firehose, stream_name)

    n = 30
    records = [{"Data": f"{i:05d}\n".encode("utf-8")} for i in range(n)]
    resp = firehose.put_record_batch(DeliveryStreamName=stream_name, Records=records)
    assert resp["FailedPutCount"] == 0, f"unexpected failures: {resp['RequestResponses']}"

    # Firehose documents at-least-once delivery (a retry can duplicate a record) and no
    # record order for S3 (https://aws.amazon.com/firehose/faqs/), so duplicates collapse.
    expected = {f"{i:05d}" for i in range(n)}
    s3 = ctx.client("s3")
    lines = _poll_until(
        lambda: _collect_s3_lines(s3, bucket),
        lambda ls: set(ls) >= expected,
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert set(lines) == expected, (
        f"delivered records must be exactly the {n} submitted: missing "
        f"{sorted(expected - set(lines))}, unexpected {sorted(set(lines) - expected)}"
    )


def _bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-").lower().replace("_", "-")
    # us-east-1 is S3's implicit default region: create_bucket rejects an explicit
    # LocationConstraint of "us-east-1" (InvalidLocationConstraint), so it must be omitted there.
    if ctx.region and ctx.region != "us-east-1":
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    else:
        s3.create_bucket(Bucket=name)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    name = ctx.unique_name("sim2real-behav-fh-stream-")
    s3_config = {
        "RoleARN": role_arn,
        "BucketARN": _bucket_arn(bucket),
        "BufferingHints": buffering_hints,
    }
    if prefix:
        s3_config["Prefix"] = prefix
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True))
    # IAM role/policy creation is eventually consistent; Firehose may reject the role as
    # not-yet-assumable for a short window. Retry the creation call itself, bounded, rather
    # than sleeping blind before it.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return name
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code != "InvalidArgumentException" or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)


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
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

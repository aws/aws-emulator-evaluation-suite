"""e2e-encryption-lifecycle-affects-delivery."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "e2e-encryption-lifecycle-affects-delivery"
GROUP = "e2e"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Toggling server-side encryption on a delivery stream (start -> enabled -> stop ->
    disabled) does not disrupt the data-plane consequence: records keep landing in S3 at
    every stage, and PutRecord's Encrypted flag tracks the current encryption status."""
    firehose = ctx.client("firehose")

    bucket_name = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket_name)
    stream_name = ctx.unique_name("sim2real-behav-fhstream-")

    _create_delivery_stream_with_retry(ctx, stream_name, role_arn, bucket_name)
    ctx.on_cleanup(lambda: _delete_stream_if_exists(ctx, stream_name))
    _wait_stream_active(ctx, stream_name)

    # Stage 1: no encryption configured yet -> PutRecord reports Encrypted False, delivers.
    marker1 = str(uuid.uuid4())
    resp1 = firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": json.dumps({"marker": marker1}).encode("utf-8")}
    )
    assert resp1["Encrypted"] is False, f"expected Encrypted=False before encryption is enabled, got {resp1['Encrypted']!r}"
    _wait_marker_delivered(ctx, bucket_name, marker1)

    # Stage 2: enable encryption, wait for ENABLED, then PutRecord reports Encrypted True.
    firehose.start_delivery_stream_encryption(
        DeliveryStreamName=stream_name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )
    _wait_encryption_status(ctx, stream_name, "ENABLED")

    marker2 = str(uuid.uuid4())
    resp2 = firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": json.dumps({"marker": marker2}).encode("utf-8")}
    )
    assert resp2["Encrypted"] is True, f"expected Encrypted=True while encryption is ENABLED, got {resp2['Encrypted']!r}"
    _wait_marker_delivered(ctx, bucket_name, marker2)

    # Stage 3: disable encryption, wait for DISABLED, PutRecord reports Encrypted False again.
    firehose.stop_delivery_stream_encryption(DeliveryStreamName=stream_name)
    _wait_encryption_status(ctx, stream_name, "DISABLED")

    marker3 = str(uuid.uuid4())
    resp3 = firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": json.dumps({"marker": marker3}).encode("utf-8")}
    )
    assert resp3["Encrypted"] is False, f"expected Encrypted=False after encryption is disabled, got {resp3['Encrypted']!r}"
    _wait_marker_delivered(ctx, bucket_name, marker3)


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-fh-")
    kwargs = {"Bucket": bucket_name}
    # S3 rejects a LocationConstraint of "us-east-1" on CreateBucket; it must be omitted there.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    ctx.on_cleanup(lambda: _delete_bucket(ctx, bucket_name))
    return bucket_name


def _delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket_name):
        objects = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objects:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": objects}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _create_firehose_role(ctx, bucket_name: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fhrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "firehose.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "firehose-s3-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload",
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:PutObject",
                ],
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_delivery_stream_with_retry(
    ctx, stream_name: str, role_arn: str, bucket_name: str, timeout_s: float = 90.0
) -> None:
    firehose = ctx.client("firehose")
    dest = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket_name}",
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=stream_name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            return
        except firehose.exceptions.InvalidArgumentException as exc:
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"CreateDeliveryStream kept failing on IAM propagation: {last_err}")


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> None:
    firehose = ctx.client("firehose")

    def probe():
        return firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    status = _poll_until(probe, lambda s: s in ("ACTIVE", "CREATING_FAILED"), timeout_s=timeout_s, interval_s=5.0)
    assert status == "ACTIVE", f"stream {stream_name} ended in status {status}"


def _wait_encryption_status(ctx, stream_name: str, expected: str, timeout_s: float = 120.0) -> None:
    firehose = ctx.client("firehose")

    def probe():
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        return desc.get("DeliveryStreamEncryptionConfiguration", {}).get("Status")

    status = _poll_until(
        probe,
        lambda s: s in (expected, "ENABLING_FAILED", "DISABLING_FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert status == expected, f"encryption status ended as {status}, expected {expected}"


def _wait_marker_delivered(ctx, bucket_name: str, marker: str, timeout_s: float = 360.0) -> None:
    s3 = ctx.client("s3")

    def probe():
        resp = s3.list_objects_v2(Bucket=bucket_name)
        for obj in resp.get("Contents", []):
            body = s3.get_object(Bucket=bucket_name, Key=obj["Key"])["Body"].read()
            if marker.encode("utf-8") in body:
                return True
        return False

    delivered = _poll_until(probe, lambda ok: ok, timeout_s=timeout_s, interval_s=10.0)
    assert delivered, f"marker {marker!r} never landed in bucket {bucket_name}"


def _delete_stream_if_exists(ctx, stream_name: str) -> None:
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    except firehose.exceptions.ResourceNotFoundException:
        pass


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        if predicate(value):
            return value
        time.sleep(interval_s)
        value = probe()
    raise AssertionError(f"{description} not met within {timeout_s}s, last saw {value!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

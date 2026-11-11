"""put-record-unicode-payload-round-trip-to-s3."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-unicode-payload-round-trip-to-s3"
GROUP = "state-machine"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A multi-byte unicode PutRecord payload is delivered to S3 byte-identical (no transcoding loss)."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    prefix = "unicode-test/"
    stream_name = _create_s3_delivery_stream(ctx, role_arn, bucket, prefix)

    payload_text = "héllo wörld — 日本語のテスト — emoji test 🎉🚀 — pi≈3.14159"
    payload = payload_text.encode("utf-8")

    firehose = ctx.client("firehose")
    resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": payload})
    assert resp["RecordId"], f"put_record returned no RecordId: {resp!r}"

    delivered = _wait_for_s3_bytes(ctx, bucket, prefix)
    assert delivered == payload, "delivered S3 bytes differ from the original UTF-8 payload"
    assert delivered.decode("utf-8") == payload_text, (
        f"delivered bytes did not decode back to the original unicode text: {delivered!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-s3-")
    if ctx.region == "us-east-1":
        # CreateBucketConfiguration.LocationConstraint must be omitted for us-east-1 --
        # S3 rejects the call if it is set to the bucket's own default region.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _create_firehose_role(ctx, bucket: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_s3_delivery_stream(ctx, role_arn: str, bucket: str, prefix: str, buffering_hints=None) -> str:
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-stream-")
    hints = buffering_hints or {"SizeInMBs": 1, "IntervalInSeconds": 60}
    config = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "Prefix": prefix,
        "BufferingHints": hints,
        "CompressionFormat": "UNCOMPRESSED",
    }
    # Newly-created IAM roles can lag briefly before Firehose can validate/assume them
    # (documented IAM eventual-consistency); retry CreateDeliveryStream on that specific
    # error rather than sleeping a fixed duration.
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    created = False
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            created = True
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException":
                last_err = e
                time.sleep(5)
                continue
            raise
    if not created:
        raise AssertionError(f"delivery stream never created (role propagation?): {last_err}")
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=name))
    _wait_for_stream_active(ctx, name)
    return name


def _wait_for_stream_active(ctx, name: str, timeout_s: float = 120.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never became ACTIVE within {timeout_s}s")


def _wait_for_s3_bytes(ctx, bucket: str, prefix: str, timeout_s: float = 240.0, interval_s: float = 15.0) -> bytes:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
        contents = resp.get("Contents", [])
        if contents:
            keys = sorted(o["Key"] for o in contents)
            data = b"".join(s3.get_object(Bucket=bucket, Key=k)["Body"].read() for k in keys)
            return data
        time.sleep(interval_s)
    raise AssertionError(f"no object ever delivered to s3://{bucket}/{prefix} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

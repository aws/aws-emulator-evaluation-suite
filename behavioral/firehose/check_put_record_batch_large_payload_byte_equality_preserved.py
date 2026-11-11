"""put-record-batch-large-payload-byte-equality-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-record-batch-large-payload-byte-equality-preserved"
GROUP = "state-machine"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A near-max-size record in PutRecordBatch is delivered to S3 with exact byte-length and content equality."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)
    prefix = "batch-large-test/"
    stream_name = _create_s3_delivery_stream(ctx, role_arn, bucket, prefix)

    # Max Firehose record size is 1,000 KiB (1,024,000 bytes); stay safely under it while
    # remaining "near max" so this is distinct from a max-size-exceeded rejection check.
    record_size = 1_000_000
    payload = bytes((i % 256) for i in range(record_size))
    assert len(payload) == record_size, f"constructed payload is {len(payload)} bytes, wanted {record_size}"

    firehose = ctx.client("firehose")
    resp = firehose.put_record_batch(
        DeliveryStreamName=stream_name, Records=[{"Data": payload}]
    )
    assert resp["FailedPutCount"] == 0, f"FailedPutCount={resp['FailedPutCount']}, expected 0: {resp['RequestResponses']!r}"
    assert len(resp["RequestResponses"]) == 1, f"expected 1 response entry, got {len(resp['RequestResponses'])}: {resp['RequestResponses']!r}"
    assert "ErrorCode" not in resp["RequestResponses"][0], f"batch entry carries an ErrorCode: {resp['RequestResponses'][0]!r}"

    delivered = _wait_for_s3_bytes(ctx, bucket, prefix, timeout_s=300.0)
    assert len(delivered) == record_size, (
        f"delivered byte length {len(delivered)} != original {record_size}"
    )
    assert delivered == payload, "delivered S3 bytes differ from the original large payload"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-s3-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]})

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
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    created = False
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
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

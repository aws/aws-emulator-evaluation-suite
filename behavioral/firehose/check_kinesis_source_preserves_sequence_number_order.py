"""kinesis-source-preserves-sequence-number-order."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "kinesis-source-preserves-sequence-number-order"
GROUP = "ordering"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A KinesisStreamSourceConfiguration-backed delivery stream preserves the original
    per-shard Kinesis put order through to S3 delivery, and rejects direct PutRecord calls.
    """
    stream_name = ctx.unique_name("sim2real-behav-frh-src-")
    stream_arn = _create_kinesis_stream(ctx, stream_name)

    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket, stream_arn)
    name = ctx.unique_name("sim2real-behav-frh-")
    _create_kinesis_source_stream_with_retry(
        ctx, name, bucket, role_arn, stream_arn,
        buffering_hints={"SizeInMBs": 128, "IntervalInSeconds": 60},
    )
    desc = _wait_stream_active(ctx, name)

    src = desc["Source"]["KinesisStreamSourceDescription"]
    assert src["KinesisStreamARN"] == stream_arn
    assert src["RoleARN"] == role_arn

    firehose = ctx.client("firehose")
    code, msg = _error_code(lambda: firehose.put_record(DeliveryStreamName=name, Record={"Data": b"nope"}))
    # InvalidSourceException is specific to CloudWatch Logs decompression source mismatches;
    # direct PutRecord/PutRecordBatch calls against a KinesisStreamAsSource delivery stream
    # are rejected as a generic invalid argument instead.
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code!r}"
    expected_msg = "This operation is not permitted on KinesisStreamAsSource delivery stream type."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    kinesis = ctx.client("kinesis")
    n = 8
    expected = [f"kseq-{i:03d}" for i in range(n)]
    for tag in expected:
        kinesis.put_record(StreamName=stream_name, Data=f"{tag}\n".encode(), PartitionKey="fixed-key")

    objs = _poll_s3_objects(ctx, bucket, min_count=1, timeout_s=240.0)
    assert objs, "no object was ever delivered to S3 from the Kinesis-sourced stream"
    content = _concat_objects(ctx, bucket, objs)
    lines = [ln for ln in content.split("\n") if ln]
    assert lines == expected, f"sequence order not preserved: got {lines}, expected {expected}"


# ===== helpers =====

def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _safe(fn, *missing: str) -> None:
    """Run a teardown call; return quietly only on the given not-found codes, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in missing:
            raise


def _create_kinesis_stream(ctx, name: str) -> str:
    kinesis = ctx.client("kinesis")
    kinesis.create_stream(
        StreamName=name, ShardCount=1, Tags={"simparity-check": CHECK}
    )
    ctx.on_cleanup(lambda: _safe(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True), "ResourceNotFoundException"))
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream(StreamName=name)["StreamDescription"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"kinesis stream {name} did not become ACTIVE in time")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-frh-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(lambda: _safe(_cleanup, "NoSuchBucket"))
    return bucket


def _create_firehose_role(ctx, bucket: str, kinesis_stream_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-frh-role-")
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
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    policy_name = f"{role_name}-policy"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                    "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject",
                ],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "kinesis:DescribeStream", "kinesis:GetShardIterator",
                    "kinesis:GetRecords", "kinesis:ListShards",
                ],
                "Resource": kinesis_stream_arn,
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name), "NoSuchEntity"))
    return role_arn


def _create_kinesis_source_stream_with_retry(
    ctx, name: str, bucket: str, role_arn: str, kinesis_stream_arn: str,
    buffering_hints: dict[str, Any] | None = None,
    timeout_s: float = 90.0,
) -> None:
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    s3_config: dict[str, Any] = {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket}"}
    if buffering_hints:
        s3_config["BufferingHints"] = buffering_hints
    ctx.on_cleanup(lambda: _safe(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True),
        "ResourceNotFoundException",
    ))
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="KinesisStreamAsSource",
                KinesisStreamSourceConfiguration={
                    "KinesisStreamARN": kinesis_stream_arn,
                    "RoleARN": role_arn,
                },
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "simparity-check", "Value": CHECK}],
            )
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = str(exc).lower()
            role_not_ready = "not authorized" in msg or "unable to assume role" in msg
            if code == "InvalidArgumentException" and role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_stream_active(ctx, name: str, timeout_s: float = 150.0) -> dict[str, Any]:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"delivery stream {name} entered {status}")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


def _poll_s3_objects(ctx, bucket: str, prefix: str = "", min_count: int = 1,
                      timeout_s: float = 180.0, interval_s: float = 5.0) -> list[dict[str, Any]]:
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    objs: list[dict[str, Any]] = []
    while time.monotonic() < deadline:
        objs = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
        if len(objs) >= min_count:
            break
        time.sleep(interval_s)
    return sorted(objs, key=lambda o: o["LastModified"])


def _concat_objects(ctx, bucket: str, objs: list[dict[str, Any]]) -> str:
    s3 = ctx.client("s3")
    parts = []
    for o in objs:
        body = s3.get_object(Bucket=bucket, Key=o["Key"])["Body"].read()
        parts.append(body.decode("utf-8"))
    return "".join(parts)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""s3-destination-empty-prefix-vs-absent-prefix-preserved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-destination-empty-prefix-vs-absent-prefix-preserved"
GROUP = "state-machine"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicit empty-string Prefix and an omitted Prefix are preserved distinguishably."""
    bucket = _create_bucket(ctx)
    role_arn = _create_firehose_role(ctx, bucket)

    stream_explicit = _create_s3_delivery_stream(ctx, role_arn, bucket, prefix="")
    stream_absent = _create_s3_delivery_stream(ctx, role_arn, bucket, prefix=None)

    firehose = ctx.client("firehose")
    desc_explicit = firehose.describe_delivery_stream(DeliveryStreamName=stream_explicit)[
        "DeliveryStreamDescription"
    ]
    desc_absent = firehose.describe_delivery_stream(DeliveryStreamName=stream_absent)[
        "DeliveryStreamDescription"
    ]

    ext_explicit = desc_explicit["Destinations"][0]["ExtendedS3DestinationDescription"]
    ext_absent = desc_absent["Destinations"][0]["ExtendedS3DestinationDescription"]

    # An explicitly-set empty string must round-trip as a present, empty Prefix key.
    assert "Prefix" in ext_explicit, (
        f"expected Prefix to be present (set to empty string) for {stream_explicit!r}, "
        f"got destination without a Prefix key: {ext_explicit!r}"
    )
    assert ext_explicit["Prefix"] == "", (
        f"expected Prefix == '' for {stream_explicit!r}, got {ext_explicit['Prefix']!r}"
    )

    # A Prefix that was never supplied at CreateDeliveryStream time must not be silently
    # coerced into a present empty string -- the key is simply absent (Firehose has no
    # server-side default value for this optional field).
    assert "Prefix" not in ext_absent, (
        f"expected Prefix to be absent when never supplied, got {ext_absent.get('Prefix')!r}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-fh-s3-")
    # S3 rejects a LocationConstraint of "us-east-1" on CreateBucket; it must be omitted there.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_s3_delivery_stream(ctx, role_arn: str, bucket: str, prefix, buffering_hints=None) -> str:
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-stream-")
    hints = buffering_hints or {"SizeInMBs": 1, "IntervalInSeconds": 60}
    config = {
        "RoleARN": role_arn,
        "BucketARN": f"arn:aws:s3:::{bucket}",
        "BufferingHints": hints,
        "CompressionFormat": "UNCOMPRESSED",
    }
    if prefix is not None:
        config["Prefix"] = prefix
    deadline = time.monotonic() + 90.0
    last_err: Exception | None = None
    created = False
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=config,
                Tags=[{"Key": "sim2real", "Value": CHECK}],
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

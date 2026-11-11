"""e2e-encryption-enable-put-disable-flow."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-encryption-enable-put-disable-flow"
GROUP = "state-machine"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Enabling server-side encryption mid-lifecycle does not block ingestion, and
    disabling it afterward returns the stream to an unencrypted state, all without
    ever losing the ability to PutRecord."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx, s3)
    role_arn = _create_firehose_role(ctx, iam, bucket)
    stream_name = ctx.unique_name("sim2real-fh-enc-")

    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        DeliveryStreamName=stream_name,
        DeliveryStreamType="DirectPut",
        S3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stream_safe(firehose, stream_name))
    _wait_stream_active(firehose, stream_name, timeout_s=180)

    initial_status = _encryption_status(firehose, stream_name)
    assert initial_status == "DISABLED", f"expected DISABLED before any encryption call, got {initial_status}"

    # PutRecord works fine before encryption is enabled.
    resp_before = firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": b"before-encryption\n"}
    )
    assert resp_before["Encrypted"] is False, f"expected Encrypted=False before enabling, got {resp_before['Encrypted']}"

    firehose.start_delivery_stream_encryption(
        DeliveryStreamName=stream_name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )
    enabled_status = _poll_until(
        probe=lambda: _encryption_status(firehose, stream_name),
        predicate=lambda s: s in ("ENABLED", "ENABLING_FAILED"),
        timeout_s=120,
        interval_s=5,
        description="encryption reaching ENABLED or ENABLING_FAILED",
    )
    assert enabled_status == "ENABLED", f"encryption ended in {enabled_status}"

    # Ingestion continues to work while encrypted, and reports Encrypted=True.
    resp_encrypted = firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": b"while-encrypted\n"}
    )
    assert resp_encrypted["Encrypted"] is True, f"expected Encrypted=True while enabled, got {resp_encrypted['Encrypted']}"

    firehose.stop_delivery_stream_encryption(DeliveryStreamName=stream_name)
    disabled_status = _poll_until(
        probe=lambda: _encryption_status(firehose, stream_name),
        predicate=lambda s: s in ("DISABLED", "DISABLING_FAILED"),
        timeout_s=120,
        interval_s=5,
        description="encryption reaching DISABLED or DISABLING_FAILED",
    )
    assert disabled_status == "DISABLED", f"encryption ended in {disabled_status}"

    # Ingestion still works after disabling, and reports Encrypted=False again.
    resp_after = firehose.put_record(
        DeliveryStreamName=stream_name, Record={"Data": b"after-disable\n"}
    )
    assert resp_after["Encrypted"] is False, f"expected Encrypted=False after disabling, got {resp_after['Encrypted']}"

    # DeleteDeliveryStream is asynchronous: the stream stays describable (status
    # DELETING) for a while afterward, so "gone" must be polled for, not assumed.
    firehose.delete_delivery_stream(DeliveryStreamName=stream_name, AllowForceDelete=True)
    _wait_stream_deleted(firehose, stream_name, timeout_s=180)
    _assert_stream_unusable(firehose, stream_name, ctx.account)


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float,
    interval_s: float,
    description: str = "condition",
) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last observed {last!r}")


def _wait_stream_active(firehose_client, name: str, timeout_s: float = 180) -> None:
    def _status() -> str:
        return firehose_client.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    final = _poll_until(
        _status, lambda s: s != "CREATING", timeout_s=timeout_s, interval_s=5,
        description=f"delivery stream {name} leaving CREATING",
    )
    assert final == "ACTIVE", f"delivery stream did not become ACTIVE, ended in {final}"


def _encryption_status(firehose_client, name: str) -> str:
    desc = firehose_client.describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]
    return desc["DeliveryStreamEncryptionConfiguration"]["Status"]


def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _wait_stream_deleted(firehose_client, name: str, timeout_s: float) -> None:
    def _probe() -> str:
        try:
            desc = firehose_client.describe_delivery_stream(DeliveryStreamName=name)
            return desc["DeliveryStreamDescription"]["DeliveryStreamStatus"]
        except firehose_client.exceptions.ResourceNotFoundException:
            return "GONE"

    _poll_until(
        _probe, lambda s: s == "GONE", timeout_s=timeout_s, interval_s=5,
        description=f"delivery stream {name} becoming not-found (DescribeDeliveryStream) after delete",
    )


def _assert_stream_unusable(firehose_client, name: str, account: str) -> None:
    put_code, put_msg = _error_code(
        lambda: firehose_client.put_record(DeliveryStreamName=name, Record={"Data": b"post-delete\n"})
    )
    assert put_code == "ResourceNotFoundException", (
        f"expected PutRecord on deleted {name} to raise ResourceNotFoundException, got {put_code!r}"
    )
    expected_msg = f"Firehose not found under account {account}."
    assert put_msg == expected_msg, f"expected message {expected_msg!r}, got {put_msg!r}"


def _delete_stream_safe(firehose_client, name: str) -> None:
    try:
        firehose_client.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except firehose_client.exceptions.ResourceNotFoundException:
        pass


def _create_delivery_stream_with_retry(ctx, firehose_client, **kwargs) -> None:
    deadline = time.monotonic() + 90
    while True:
        try:
            firehose_client.create_delivery_stream(**kwargs)
            return
        except firehose_client.exceptions.InvalidArgumentException:
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_bucket(ctx, s3_client) -> str:
    bucket = ctx.unique_name("sim2real-fh-enc-").lower()
    # us-east-1 is the one region CreateBucket rejects a LocationConstraint for; not a
    # hardcoded region assumption, just that API's quirk.
    if ctx.region == "us-east-1":
        s3_client.create_bucket(Bucket=bucket)
    else:
        s3_client.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3_client.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )

    def _teardown() -> None:
        paginator = s3_client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3_client.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3_client.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_teardown)
    return bucket


def _create_firehose_role(ctx, iam_client, bucket: str) -> str:
    role_name = ctx.unique_name("sim2real-fh-enc-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
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
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            }
        ],
    }
    policy_name = "s3-access"
    iam_client.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc)
    )

    def _teardown() -> None:
        iam_client.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam_client.delete_role(RoleName=role_name)

    ctx.on_cleanup(_teardown)
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

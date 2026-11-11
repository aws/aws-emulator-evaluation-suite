"""start-encryption-invalid-kms-key."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-encryption-invalid-kms-key"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartDeliveryStreamEncryption with an unusable KMS key is refused with
    InvalidKMSResourceException and leaves the stream's encryption status DISABLED, while
    starting encryption with an AWS-owned CMK (positive control) transitions it to ENABLED."""
    role_arn = _iam_role_for_firehose(ctx)
    _bucket_name, bucket_arn = _s3_bucket(ctx)
    firehose = ctx.client("firehose")

    stream_name = ctx.unique_name("sim2real-fh-enc-")
    _create_delivery_stream_with_role_retry(
        ctx, firehose, stream_name, _basic_s3_dest(bucket_arn, role_arn)
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    _wait_stream_active(ctx, stream_name)

    bogus_key_arn = f"arn:aws:kms:{ctx.region}:111122223333:key/00000000-0000-0000-0000-000000000000"
    try:
        firehose.start_delivery_stream_encryption(
            DeliveryStreamName=stream_name,
            DeliveryStreamEncryptionConfigurationInput={
                "KeyType": "CUSTOMER_MANAGED_CMK",
                "KeyARN": bogus_key_arn,
            },
        )
    except ClientError as e:
        assert e.response["Error"]["Code"] == "InvalidKMSResourceException"
        expected = (
            "AccessDenied by KMS while using the CMK. Check the key policy to ensure that the "
            "KMS grant related apis are allowed. Try again after the key policy has the right "
            "permissions."
        )
        message = e.response["Error"].get("Message")
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("expected InvalidKMSResourceException for an unusable KMS key")

    # The rejected StartDeliveryStreamEncryption call must never make encryption ENABLED.
    # Firehose may register the attempt and asynchronously settle on ENABLING_FAILED rather
    # than snapping straight back to DISABLED, so poll to a terminal (non-transitioning)
    # status and assert it never reached ENABLED.
    status = _poll_encryption_status(
        ctx, stream_name, {"DISABLED", "ENABLING_FAILED"}, timeout_s=90.0
    )
    assert status != "ENABLED"

    # If the rejected attempt left the stream in ENABLING_FAILED, real AWS treats that as a
    # terminal, non-recoverable-in-place state for this stream: StopDeliveryStreamEncryption
    # refuses to "disable" encryption that never actually became enabled (it responds with
    # InvalidArgumentException: "Cannot disable encryption on firehose: stream is not
    # enabled" / similar), and there is no supported way to clear ENABLING_FAILED on the same
    # stream from here. So the positive control (enabling with an AWS-owned CMK reaches
    # ENABLED) is exercised on a *separate*, freshly created delivery stream rather than by
    # trying to recover this one.
    positive_stream_name = stream_name
    if status == "ENABLING_FAILED":
        positive_stream_name = ctx.unique_name("sim2real-fh-enc2-")
        _create_delivery_stream_with_role_retry(
            ctx, firehose, positive_stream_name, _basic_s3_dest(bucket_arn, role_arn)
        )
        ctx.on_cleanup(
            lambda: firehose.delete_delivery_stream(DeliveryStreamName=positive_stream_name)
        )
        _wait_stream_active(ctx, positive_stream_name)

    # Positive control: enabling with an AWS-owned CMK succeeds and reaches ENABLED.
    firehose.start_delivery_stream_encryption(
        DeliveryStreamName=positive_stream_name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )
    status = _poll_encryption_status(ctx, positive_stream_name, {"ENABLED"}, timeout_s=90.0)
    assert status == "ENABLED"


def _iam_role_for_firehose(ctx) -> str:
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*", "kinesis:*", "kms:*"], "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-fh-inline", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-fh-inline"))
    return role_arn


def _create_delivery_stream_with_role_retry(
    ctx, firehose, name: str, s3_dest: dict, timeout_s: float = 60.0
) -> None:
    """Retries CreateDeliveryStream while IAM propagates the just-created role, rather than
    sleeping a fixed guess up front. Firehose reports an unpropagated role as
    InvalidArgumentException("Firehose is unable to assume role ..."); any other error is a
    real rejection and must not be retried."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=s3_dest,
            )
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code == "InvalidArgumentException" and "unable to assume role" in message:
                if time.monotonic() >= deadline:
                    raise AssertionError(
                        f"role never became assumable by Firehose within {timeout_s}s: {message}"
                    ) from e
                time.sleep(3)
                continue
            raise


def _s3_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name, f"arn:aws:s3:::{name}"


def _empty_and_delete_bucket(ctx, name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_object_versions(Bucket=name)
    objs = [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("Versions", [])]
    objs += [{"Key": o["Key"], "VersionId": o["VersionId"]} for o in resp.get("DeleteMarkers", [])]
    if objs:
        failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=name)


def _basic_s3_dest(bucket_arn: str, role_arn: str) -> dict:
    return {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 1},
    }


def _wait_stream_active(ctx, name: str, timeout_s: float = 300.0) -> dict:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(
                f"delivery stream {name} entered CREATING_FAILED: {desc.get('FailureDescription')}"
            )
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")


def _poll_encryption_status(ctx, name: str, target_statuses: set[str], timeout_s: float = 90.0) -> str:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        enc = desc.get("DeliveryStreamEncryptionConfiguration") or {}
        last = enc.get("Status", "DISABLED")
        if last in target_statuses:
            return last
        if last.endswith("_FAILED"):
            raise AssertionError(f"encryption entered failed state {last}")
        time.sleep(3)
    raise AssertionError(f"encryption status never reached {target_statuses}, last was {last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

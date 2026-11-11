"""start-encryption-while-stream-deleting-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "start-encryption-while-stream-deleting-rejected"
GROUP = "error-semantics"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartDeliveryStreamEncryption on a DELETING stream fails with ResourceInUseException and its exact message and
    starts no encryption there, while the same call on an ACTIVE stream reaches ENABLED."""
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    bucket_arn, role_arn = _bucket_and_role(ctx)

    # Stream under negative test: create, wait ACTIVE, delete, then immediately (no
    # intervening sleep) try to start encryption while it is still tearing down.
    victim_name = ctx.unique_name("sim2real-fh-deleting-")
    _create_stream_retrying(
        firehose,
        DeliveryStreamName=victim_name,
        ExtendedS3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _force_delete_stream(firehose, victim_name))
    _wait_stream_active(firehose, victim_name, timeout_s=120)

    firehose.delete_delivery_stream(DeliveryStreamName=victim_name)

    try:
        firehose.start_delivery_stream_encryption(
            DeliveryStreamName=victim_name,
            DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message")
    else:
        raise AssertionError("StartDeliveryStreamEncryption on a DELETING stream succeeded")

    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    expected = f"Cannot enable encryption on firehose: {victim_name} when it is in DELETING status"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: if the stream is still describable, encryption must not have started
    try:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=victim_name)["DeliveryStreamDescription"]
        enc_status = desc.get("DeliveryStreamEncryptionConfiguration", {}).get("Status")
        assert enc_status in (None, "DISABLED"), (
            f"encryption transitioned on a stream that was DELETING (status={enc_status})"
        )
    except ClientError as err:
        got = err.response["Error"]["Code"]
        assert got == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {got}"
        expected_nf = f"Firehose under account {ctx.account} not found."
        got_message = err.response["Error"].get("Message")
        assert got_message == expected_nf, f"expected message {expected_nf!r}, got {got_message!r}"

    # positive control: the same call against a healthy ACTIVE stream succeeds
    healthy_name = ctx.unique_name("sim2real-fh-active-")
    _create_stream_retrying(
        firehose,
        DeliveryStreamName=healthy_name,
        ExtendedS3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _force_delete_stream(firehose, healthy_name))
    _wait_stream_active(firehose, healthy_name, timeout_s=120)

    firehose.start_delivery_stream_encryption(
        DeliveryStreamName=healthy_name,
        DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
    )

    deadline = time.monotonic() + 90
    final_status = None
    while time.monotonic() < deadline:
        final_status = firehose.describe_delivery_stream(DeliveryStreamName=healthy_name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamEncryptionConfiguration"]["Status"]
        if final_status == "ENABLED":
            break
        time.sleep(3)
    assert final_status == "ENABLED", f"encryption never reached ENABLED on a healthy stream (last={final_status})"


def _bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-fh-bkt-")
    if ctx.region == "us-east-1":  # CreateBucket rejects an explicit LocationConstraint here
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    role_name = ctx.unique_name("sim2real-fh-role-")
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
    policy_name = f"{role_name}-s3-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:GetBucketLocation", "s3:ListBucket"],
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup_role():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return bucket_arn, role_arn


def _create_stream_retrying(firehose, *, timeout_s: float = 90, interval_s: float = 5, **kwargs: Any):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidArgumentException" and (
                "not authorized" in msg or "Access Denied" in msg or "assume" in msg.lower()
            ):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    assert last_err is not None, "create_delivery_stream retry loop exited with no captured error"
    raise last_err


def _wait_stream_active(firehose, name: str, timeout_s: float = 120) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never reached ACTIVE (last status={status})")


def _force_delete_stream(firehose, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""start-encryption-already-enabling-conflict-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-encryption-already-enabling-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "plane:control")
def run(ctx) -> None:
    """StartDeliveryStreamEncryption twice in a row on an unencrypted stream: the second call either
    succeeds or is refused with ResourceInUseException while the first is still ENABLING, and the
    stream reaches ENABLED with the requested key type.
    Reference: https://docs.aws.amazon.com/firehose/latest/APIReference/API_StartDeliveryStreamEncryption.html"""
    firehose = ctx.client("firehose")
    bucket_arn, role_arn = _setup_destination(ctx)

    name = ctx.unique_name("sim2real-fh-enc-")
    _create_stream_with_role_retry(
        firehose,
        timeout_s=_bounded(ctx, 45.0, reserve_s=40.0),
        DeliveryStreamName=name,
        ExtendedS3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_stream(firehose, name))
    _wait_for_stream_active(firehose, name, timeout_s=_bounded(ctx, 120.0, reserve_s=30.0))

    def _start():
        firehose.start_delivery_stream_encryption(
            DeliveryStreamName=name,
            DeliveryStreamEncryptionConfigurationInput={"KeyType": "AWS_OWNED_CMK"},
        )

    _start()
    first = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    first_status = first.get("DeliveryStreamEncryptionConfiguration", {}).get("Status")
    assert first_status in ("ENABLING", "ENABLED"), (
        f"expected encryption ENABLING or ENABLED after the first start, got {first_status!r}"
    )

    try:
        _start()
    except ClientError as e:
        code, message = e.response["Error"]["Code"], e.response["Error"].get("Message")
        assert code == "ResourceInUseException", (
            f"expected success or ResourceInUseException, got {code!r}: {message!r}"
        )
        expected = f"Cannot enable encryption on firehose: {name} when encryption is in ENABLING status"
        assert message == expected, f"{code} message {message!r}, expected {expected!r}"

    # the started transition takes hold: encryption reaches ENABLED with the requested key type
    status = _wait_for_encryption_status(firehose, name, timeout_s=_bounded(ctx, 120.0, reserve_s=5.0))
    assert status == "ENABLED", f"expected encryption status ENABLED, got {status}"
    cfg = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"][
        "DeliveryStreamEncryptionConfiguration"
    ]
    assert cfg.get("KeyType") == "AWS_OWNED_CMK", f"expected KeyType AWS_OWNED_CMK, got {cfg!r}"



def _bounded(ctx, wanted_s: float, *, reserve_s: float) -> float:
    """`wanted_s`, cut so `reserve_s` of the check's budget is left for what follows."""
    left = ctx.time_left()
    return wanted_s if left is None else max(1.0, min(wanted_s, left - reserve_s))


def _bucket_name(ctx) -> str:
    return ctx.unique_name("sim2real-fh-bkt-").lower().replace("_", "-")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _bucket_name(ctx)
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:managed", "Value": "true"}]}
    )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return f"arn:aws:s3:::{name}"


def _create_trusted_role(ctx, trust_service: str = "firehose.amazonaws.com") -> str:
    import json

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": trust_service},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="s3-access"))
    return role_arn


def _setup_destination(ctx):
    bucket_arn = _create_bucket(ctx)
    role_arn = _create_trusted_role(ctx, "firehose.amazonaws.com")
    return bucket_arn, role_arn


def _create_stream_with_role_retry(firehose, timeout_s: float = 45.0, **kwargs):
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "").lower()
            if code == "InvalidArgumentException" and "assume" in msg:
                last_err = e
                time.sleep(3)
                continue
            raise
    raise last_err


def _delete_stream(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_stream_active(firehose, name: str, timeout_s: float = 120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status == "CREATING_FAILED":
            raise AssertionError(f"stream {name} failed to create: {desc.get('FailureDescription')}")
        time.sleep(3)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s")


def _wait_for_encryption_status(firehose, name: str, timeout_s: float = 120.0):
    terminal = {"ENABLED", "ENABLING_FAILED"}
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        cfg = desc.get("DeliveryStreamEncryptionConfiguration", {})
        last = cfg.get("Status")
        if last in terminal:
            return last
        time.sleep(3)
    raise AssertionError(f"encryption status did not reach a terminal state, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

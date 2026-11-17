"""list-delivery-streams-malformed-cursor-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-delivery-streams-malformed-cursor-rejected"
GROUP = "boundary-validation"
SERVICES = ["firehose"]

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


def _bucket_policy(bucket: str) -> dict:
    return {
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


def _refusal(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; a success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _drop_role(iam, role_name: str, policy_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _empty_and_drop_bucket(s3, bucket: str) -> None:
    try:
        objects = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objects:
            s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": [{"Key": o["Key"]} for o in objects]},
            )
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _drop_stream(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_active(firehose, name: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"{name} did not reach ACTIVE within {timeout_s}s")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListDeliveryStreams rejects an ExclusiveStartDeliveryStreamName that violates the
    cursor's character pattern and one that exceeds its length, each with a distinct
    ValidationException message, while a well-formed call still lists the stream.
    """
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-behav-fh-lds-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_drop_bucket(s3, bucket))

    role_name = ctx.unique_name("sim2real-behav-fh-lds-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY)
    )["Role"]["Arn"]
    policy_name = f"{role_name}-access"
    ctx.on_cleanup(lambda: _drop_role(iam, role_name, policy_name))
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(_bucket_policy(bucket))
    )

    name = ctx.unique_name("sim2real-behav-fh-lds-")
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                S3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": f"arn:aws:s3:::{bucket}",
                },
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    ctx.on_cleanup(lambda: _drop_stream(firehose, name))
    _wait_active(firehose, name)

    # Positive control: a well-formed call finds our stream before either malformed one runs.
    before = firehose.list_delivery_streams(DeliveryStreamType="DirectPut", Limit=10000)
    assert name in before["DeliveryStreamNames"], (
        f"expected {name!r} among DirectPut streams, got "
        f"{len(before['DeliveryStreamNames'])} name(s) not including it"
    )

    code_pattern, msg_pattern = _refusal(
        lambda: firehose.list_delivery_streams(ExclusiveStartDeliveryStreamName="not a valid name!")
    )
    assert code_pattern == "ValidationException", f"expected ValidationException, got {code_pattern}"
    expected_pattern_msg = (
        "1 validation error detected: Value at 'exclusiveStartDeliveryStreamName' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+"
    )
    assert msg_pattern == expected_pattern_msg, f"expected message {expected_pattern_msg!r}, got {msg_pattern!r}"

    code_length, msg_length = _refusal(
        lambda: firehose.list_delivery_streams(ExclusiveStartDeliveryStreamName="x" * 65)
    )
    assert code_length == "ValidationException", f"expected ValidationException, got {code_length}"
    expected_length_msg = (
        "1 validation error detected: Value at 'exclusiveStartDeliveryStreamName' failed to "
        "satisfy constraint: Member must have length less than or equal to 64"
    )
    assert msg_length == expected_length_msg, f"expected message {expected_length_msg!r}, got {msg_length!r}"
    assert (code_pattern, msg_pattern) != (code_length, msg_length), (
        "the two malformed-cursor rejections must be distinguishable"
    )

    # Neither rejection leaves a mark: the well-formed call still finds the stream.
    after = firehose.list_delivery_streams(DeliveryStreamType="DirectPut", Limit=10000)
    assert name in after["DeliveryStreamNames"], (
        f"expected {name!r} still listable after the two rejected calls, got "
        f"{len(after['DeliveryStreamNames'])} name(s) not including it"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""create-stream-name-exceeds-length-limit-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-stream-name-exceeds-length-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A 65-character DeliveryStreamName (model max 64) is rejected by the service with
    ValidationException and creates no stream; a 64-character name is accepted and reaches
    ACTIVE."""
    from botocore.exceptions import ClientError

    firehose = ctx.client("firehose")
    bucket_arn, role_arn = _bucket_and_role(ctx)

    # botocore does not enforce this length client-side, so the request reaches the service.
    too_long_name = "a" * 65
    try:
        firehose.create_delivery_stream(
            DeliveryStreamName=too_long_name,
            ExtendedS3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
        )
        raise AssertionError("CreateDeliveryStream accepted a 65-character DeliveryStreamName")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ValidationException", f"expected ValidationException, got {code}"
        message = err.response["Error"].get("Message")
        expected = "1 validation error detected: Value at 'deliveryStreamName' failed to satisfy constraint: Member must have length less than or equal to 64"
        assert message == expected, f"expected message {expected!r}, got {message!r}"

    # DescribeDeliveryStream validates the same length constraint, so it refuses the name too.
    not_found_code, not_found_message = _describe_error(firehose, too_long_name)
    assert not_found_code == "ValidationException", (
        f"rejected CreateDeliveryStream still left behind a stream (code={not_found_code})"
    )
    expected = "1 validation error detected: Value at 'deliveryStreamName' failed to satisfy constraint: Member must have length less than or equal to 64"
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # positive control: exactly the boundary maximum (64 chars) is accepted
    base = ctx.unique_name("sim2real-fh-len-")
    good_name = (base + "a" * 64)[:64]
    assert len(good_name) == 64
    _create_stream_retrying(
        firehose,
        DeliveryStreamName=good_name,
        ExtendedS3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _force_delete_stream(firehose, good_name))
    _wait_stream_active(firehose, good_name, timeout_s=120)

    # Deletion is asynchronous (the stream sits in DELETING first), so not-found is a bounded poll.
    _force_delete_stream(firehose, good_name)
    _wait_stream_deleted(firehose, good_name, timeout_s=120)
    deleted_code, deleted_message = _describe_error(firehose, good_name)
    assert deleted_code == "ResourceNotFoundException", (
        f"deleted delivery stream {good_name} still describes as {deleted_code}"
    )
    expected = f"Firehose under account {ctx.account} not found."
    assert deleted_message == expected, f"expected message {expected!r}, got {deleted_message!r}"
    try:
        firehose.tag_delivery_stream(DeliveryStreamName=good_name, Tags=[{"Key": "x", "Value": "y"}])
        raise AssertionError(f"TagDeliveryStream succeeded against deleted stream {good_name}")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        message = err.response["Error"].get("Message")
        expected = f"Firehose under account {ctx.account} not found."
        assert message == expected, f"expected message {expected!r}, got {message!r}"


def _describe_error(firehose, name: str):
    """DescribeDeliveryStream(name); return (Error.Code, Error.Message) of its ClientError.
    A successful describe raises: the stream is expected not to exist."""
    from botocore.exceptions import ClientError
    try:
        result = firehose.describe_delivery_stream(DeliveryStreamName=name)
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected DescribeDeliveryStream({name!r}) to fail, but it returned {result!r}")


def _bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-fh-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    assert last_err is not None
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


def _wait_stream_deleted(firehose, name: str, timeout_s: float = 120) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = firehose.describe_delivery_stream(DeliveryStreamName=name)[
                "DeliveryStreamDescription"
            ]["DeliveryStreamStatus"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never disappeared (last status={last_status})")


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

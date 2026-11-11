"""create-stream-buffering-size-above-maximum-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-stream-buffering-size-above-maximum-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """BufferingHints.SizeInMBs above 128 is rejected with ValidationException and creates no
    stream. The boundary value 128 succeeds and round-trips on Describe, so the rejection is
    value-specific."""
    firehose = ctx.client("firehose")
    bucket_arn, role_arn = _bucket_and_role(ctx)

    bad_name = ctx.unique_name("sim2real-fh-badsize-")
    code, message = _error_code(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=bad_name,
            ExtendedS3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": bucket_arn,
                "BufferingHints": {"SizeInMBs": 500, "IntervalInSeconds": 300},
            },
        )
    )

    # SizeInMBs has a model range constraint (1-128), so it fails request validation with
    # ValidationException, unlike IntervalInSeconds, which raises InvalidArgumentException.
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "1 validation error detected: Value at 'extendedS3DestinationConfiguration.bufferingHints.sizeInMBs' failed to satisfy constraint: Member must have value less than or equal to 128"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error_code(lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected CreateDeliveryStream still left behind a stream (code={not_found_code})"
    )
    expected = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # positive control: the documented maximum (128 MiB) is accepted
    good_name = ctx.unique_name("sim2real-fh-goodsize-")
    _create_stream_retrying(
        firehose,
        DeliveryStreamName=good_name,
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": bucket_arn,
            "BufferingHints": {"SizeInMBs": 128, "IntervalInSeconds": 300},
        },
    )
    ctx.on_cleanup(lambda: _force_delete_stream(firehose, good_name))
    _wait_stream_active(firehose, good_name, timeout_s=120)

    hints = firehose.describe_delivery_stream(DeliveryStreamName=good_name)[
        "DeliveryStreamDescription"
    ]["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]
    assert hints == {"SizeInMBs": 128, "IntervalInSeconds": 300}, (
        f"the accepted boundary value must round-trip verbatim, got {hints!r}"
    )


def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message) of its ClientError. An unexpected
    success raises, so a target accepting what AWS refuses cannot read as a mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-fh-bkt-")
    if ctx.region == "us-east-1":
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
    assert last_err is not None, "retry loop exited with no error recorded and no stream created"
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

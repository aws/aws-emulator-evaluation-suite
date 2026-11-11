"""create-stream-buffering-interval-below-minimum-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-stream-buffering-interval-below-minimum-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream with BufferingHints.IntervalInSeconds=-1 (below the minimum of 0) is
    rejected with ValidationException and creates no stream; the same config with 0 succeeds."""
    firehose = ctx.client("firehose")
    bucket_arn, role_arn = _bucket_and_role(ctx)

    # botocore enforces the modelled minimum client-side, so the out-of-range value is sent
    # through a client with parameter validation disabled.
    raw = _raw_client_no_validation(ctx, "firehose")
    bad_name = ctx.unique_name("sim2real-fh-badinterval-")
    code, message = _error_code(
        lambda: raw.create_delivery_stream(
            DeliveryStreamName=bad_name,
            ExtendedS3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": bucket_arn,
                "BufferingHints": {"SizeInMBs": 5, "IntervalInSeconds": -1},
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'extendedS3DestinationConfiguration.bufferingHints."
        "intervalInSeconds' failed to satisfy constraint: Member must have value greater than or equal to 0"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no stream was actually created under that name
    not_found_code, not_found_message = _error_code(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_name)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected CreateDeliveryStream still left behind a stream (code={not_found_code})"
    )
    expected = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # positive control: the modelled minimum (0s) is accepted
    good_name = ctx.unique_name("sim2real-fh-goodinterval-")
    _create_stream_retrying(
        firehose,
        DeliveryStreamName=good_name,
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": bucket_arn,
            "BufferingHints": {"SizeInMBs": 5, "IntervalInSeconds": 0},
        },
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _force_delete_stream(firehose, good_name))
    _wait_stream_active(firehose, good_name, timeout_s=120)
    hints = firehose.describe_delivery_stream(DeliveryStreamName=good_name)[
        "DeliveryStreamDescription"]["Destinations"][0]["ExtendedS3DestinationDescription"]["BufferingHints"]
    assert hints == {"SizeInMBs": 5, "IntervalInSeconds": 0}, f"expected the stored hints to echo the request, got {hints}"


def _error_code(fn):
    """Call fn() and return (Code, Message) of the ClientError it raised; an unexpected success raises."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _raw_client_no_validation(ctx, service):
    """A client with botocore parameter validation disabled, so out-of-range values reach the service."""
    from botocore.config import Config

    return ctx.client(service, config=Config(parameter_validation=False))


def _bucket_and_role(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    iam = ctx.client("iam")
    bucket = ctx.unique_name("sim2real-fh-bkt-")
    # us-east-1 is the one region S3 CreateBucket rejects a LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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

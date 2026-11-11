"""create-stream-buffering-interval-out-of-range-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-buffering-interval-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream rejects an S3 BufferingHints.IntervalInSeconds above
    the documented maximum of 900 rather than clamping it, and leaves no
    delivery stream behind; the same config with an in-range interval succeeds."""
    firehose = ctx.client("firehose")
    bucket_arn, role_arn = _setup_destination(ctx)

    bad_name = ctx.unique_name("sim2real-fh-badbuf-")
    code, message = _error_code(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=bad_name,
            ExtendedS3DestinationConfiguration={
                "RoleARN": role_arn,
                "BucketARN": bucket_arn,
                "BufferingHints": {"IntervalInSeconds": 1000, "SizeInMBs": 5},
            },
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = "1 validation error detected: Value at 'extendedS3DestinationConfiguration.bufferingHints.intervalInSeconds' failed to satisfy constraint: Member must have value less than or equal to 900"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no delivery stream with the rejected config was created
    code2, message2 = _error_code(lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_name))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected = f"Firehose under account {ctx.account} not found."
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"

    # positive control: an in-range interval on the same destination succeeds
    good_name = ctx.unique_name("sim2real-fh-goodbuf-")
    _create_stream_with_role_retry(
        firehose,
        DeliveryStreamName=good_name,
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_arn,
            "BucketARN": bucket_arn,
            "BufferingHints": {"IntervalInSeconds": 300, "SizeInMBs": 5},
        },
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    ctx.on_cleanup(lambda: _delete_stream(firehose, good_name))
    desc = _wait_for_stream_active(firehose, good_name)
    dest = desc["Destinations"][0]["ExtendedS3DestinationDescription"]
    got_interval = dest["BufferingHints"]["IntervalInSeconds"]
    assert got_interval == 300, f"expected the in-range interval to round-trip as 300, got {got_interval}"


# ===== helpers =====

def _error_code(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, so an
    over-permissive target cannot pass acceptance off as a plain code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _bucket_name(ctx) -> str:
    return ctx.unique_name("sim2real-fh-bkt-").lower().replace("_", "-")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _bucket_name(ctx)
    # us-east-1 is region-pinned here only for the S3 CreateBucket call shape: that
    # region is the one where CreateBucketConfiguration/LocationConstraint must be
    # omitted, not a hardcoded target region for the check itself.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
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
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
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


def _delete_stream(firehose, name: str, timeout_s: float = 180.0) -> None:
    """DeleteDeliveryStream returns while the stream is still DELETING, so a fire-and-forget call
    can leak it -- poll to actual disappearance instead."""
    deadline = time.monotonic() + timeout_s
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"LEAK: delivery stream {name} still present after {timeout_s}s")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

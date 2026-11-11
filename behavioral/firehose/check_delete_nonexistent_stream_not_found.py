"""delete-nonexistent-stream-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-nonexistent-stream-not-found"
GROUP = 'error-semantics'
SERVICES = ['firehose']


def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteDeliveryStream on a never-created name fails with ResourceNotFoundException and its exact message, and
    a second delete of a real stream that was deleted fails the same way."""
    firehose = ctx.client("firehose")

    # Positive control: DeleteDeliveryStream against a real, existing stream succeeds.
    role_arn = _delivery_role_arn(ctx)
    bucket_arn = _make_bucket(ctx)
    stream_name = ctx.unique_name("sim2real-behav-fh-del-")
    _create_stream(ctx, stream_name, role_arn, bucket_arn)
    _wait_active(ctx, stream_name)

    firehose.delete_delivery_stream(DeliveryStreamName=stream_name)
    _wait_gone(ctx, stream_name)

    # Negative: DeleteDeliveryStream on a name that was never created at all.
    never_created = ctx.unique_name("sim2real-behav-fh-never-created-")
    code, msg = _error_code(lambda: firehose.delete_delivery_stream(DeliveryStreamName=never_created))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected_msg = f"Firehose under account {ctx.account} not found."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # The dead id stays dead: a second delete on the just-removed stream fails
    # the identical way, not with some other code implying partial state.
    code2, msg2 = _error_code(lambda: firehose.delete_delivery_stream(DeliveryStreamName=stream_name))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    assert msg2 == expected_msg, f"expected message {expected_msg!r}, got {msg2!r}"


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

_ACCESS_POLICY = {
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
            "Resource": "*",
        }
    ],
}


def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "NoSuchBucket",
            "NoSuchEntity",
            "ResourceNotFoundException",
        ):
            raise


def _delivery_role_arn(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-role-")
    role_arn = iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=json.dumps(_TRUST_POLICY)
    )["Role"]["Arn"]
    iam.put_role_policy(
        RoleName=name, PolicyName="firehose-destination-access",
        PolicyDocument=json.dumps(_ACCESS_POLICY),
    )

    def _teardown():
        _swallow(lambda: iam.delete_role_policy(RoleName=name, PolicyName="firehose-destination-access"))
        _swallow(lambda: iam.delete_role(RoleName=name))

    ctx.on_cleanup(_teardown)
    return role_arn


def _make_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-dst-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _teardown():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            _swallow(lambda: s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ))
        _swallow(lambda: s3.delete_bucket(Bucket=name))

    ctx.on_cleanup(_teardown)
    return f"arn:aws:s3:::{name}"


def _create_stream(ctx, name: str, role_arn: str, bucket_arn: str) -> None:
    """Create a delivery stream, retrying while the freshly created role is
    still propagating (Firehose rejects a brand-new role until it is visible)."""
    firehose = ctx.client("firehose")
    ctx.on_cleanup(lambda: _swallow(
        lambda: firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    ))
    deadline = time.monotonic() + 60.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                ExtendedS3DestinationConfiguration={
                    "RoleARN": role_arn,
                    "BucketARN": bucket_arn,
                    "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
                },
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = (exc.response.get("Error", {}).get("Message") or "").lower()
            propagating = code == "InvalidArgumentException" and (
                "assume" in msg or "not authorized" in msg or "does not exist" in msg
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _wait_active(ctx, name: str, timeout_s: float = 100.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        last = desc["DeliveryStreamStatus"]
        if last == "ACTIVE":
            return
        if last == "CREATING_FAILED":
            raise AssertionError(f"stream {name} entered CREATING_FAILED: {desc.get('FailureDescription')}")
        time.sleep(3)
    raise AssertionError(f"stream {name} did not become ACTIVE within {timeout_s}s (last={last})")


def _wait_gone(ctx, name: str, timeout_s: float = 120.0) -> None:
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            raise
        else:
            last = "still describable"
        time.sleep(3)
    raise AssertionError(f"stream {name} was not fully deleted within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

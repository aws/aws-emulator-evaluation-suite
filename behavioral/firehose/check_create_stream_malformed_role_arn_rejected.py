"""create-stream-malformed-role-arn-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-stream-malformed-role-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream with RoleARN "not-a-valid-arn" fails with InvalidParameterValueException "Invalid role
    ARN.", the name stays not-found, and the same create with a real role ARN succeeds."""
    firehose = ctx.client("firehose")
    bucket_arn, real_role_arn = _bucket_and_role(ctx)

    bad_name = ctx.unique_name("sim2real-fh-badarn-")
    malformed_role_arn = "not-a-valid-arn"
    code, message = _error_code(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=bad_name,
            ExtendedS3DestinationConfiguration={
                "RoleARN": malformed_role_arn,
                "BucketARN": bucket_arn,
            },
        )
    )

    # A syntactically invalid RoleARN is rejected with InvalidParameterValueException, distinct from
    # the well-formed-but-unassumable-role case (InvalidArgumentException).
    assert code == "InvalidParameterValueException", f"CODE={code} expected InvalidParameterValueException"
    expected = "Invalid role ARN."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error_code(lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"rejected CreateDeliveryStream with a malformed RoleARN still left behind a stream (code={not_found_code})"
    )
    expected = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # positive control: a syntactically valid role ARN for the same bucket succeeds
    good_name = ctx.unique_name("sim2real-fh-goodarn-")
    _create_stream_retrying(
        firehose,
        DeliveryStreamName=good_name,
        ExtendedS3DestinationConfiguration={
            "RoleARN": real_role_arn,
            "BucketARN": bucket_arn,
        },
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _force_delete_stream(firehose, good_name))
    _wait_stream_active(firehose, good_name, timeout_s=120)


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
        if status.endswith("_FAILED"):
            raise AssertionError(f"delivery stream {name} entered {status}")
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

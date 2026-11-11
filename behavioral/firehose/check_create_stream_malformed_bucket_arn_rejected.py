"""create-stream-malformed-bucket-arn-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Callable, Iterable, Optional

from behavioral_harness import tags

CHECK = "create-stream-malformed-bucket-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream rejects a non `arn:aws:s3:::...` BucketARN in the S3
    destination config, and never creates the stream. A valid ARN with the same role
    succeeds."""
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")

    bucket_name = ctx.unique_name("sim2real-behav-fhbucket-")
    _create_bucket(ctx, s3, bucket_name)
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    role_arn = _create_role(ctx, iam, "sim2real-behav-fhrole-", "firehose.amazonaws.com", bucket_arn)

    # Positive control FIRST: establish that this role is warmed up / assumable so the
    # negative attempt below can only fail because of the malformed ARN, not IAM lag.
    good_stream_name = ctx.unique_name("sim2real-behav-fhstream-good-")
    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        DeliveryStreamName=good_stream_name,
        S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": bucket_arn},
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=good_stream_name, AllowForceDelete=True))
    status = _wait_for_stream_status(ctx, firehose, good_stream_name, {"ACTIVE", "CREATING_FAILED"})
    assert status == "ACTIVE", f"expected positive control to reach ACTIVE, got {status}"

    # Negative: same warmed-up role, malformed BucketARN.
    bad_stream_name = ctx.unique_name("sim2real-behav-fhstream-bad-")
    code, message = _error_code_and_message(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=bad_stream_name,
            S3DestinationConfiguration={"RoleARN": role_arn, "BucketARN": "not-an-s3-arn"},
            Tags=[{"Key": "simparity-check", "Value": CHECK}],
        )
    )
    # Empirically (real AWS), a malformed BucketARN fails constraint validation at the
    # API-shape level and is reported as ValidationException, not InvalidArgumentException
    # (that code is reserved for semantically-valid-shape values the service rejects, e.g.
    # a well-formed but nonexistent/untrusted ARN).
    assert code == "ValidationException", f"CODE={code}"
    # The generic request validator names the offending member and quotes the pattern it
    # applied, so a ValidationException about some OTHER member must not pass.
    expected = (
        "1 validation error detected: Value at 's3DestinationConfiguration.bucketARN' failed to satisfy constraint: Member must satisfy regular expression pattern: " + r"arn:.*:s3:::[\w\.\-]{1,255}"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    not_found_code, not_found_message = _error_code_and_message(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_stream_name)
    )
    assert not_found_code == "ResourceNotFoundException", f"expected stream absent, got {not_found_code}"
    expected = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"


def _error_code_and_message(fn: Callable[[], Any]) -> tuple[Optional[str], str]:
    """Call fn(); return (Error.Code, Error.Message) on ClientError. An unexpected SUCCESS raises --
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], error.get("Message") or ""
    raise AssertionError(f"expected a ClientError, call succeeded and returned {result!r}")


def _create_bucket(ctx, s3, name: str) -> None:
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "simparity-check", "Value": CHECK}]})

    def _cleanup() -> None:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)


def _create_role(ctx, iam, prefix: str, trust_service: str, bucket_arn: str) -> str:
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role_name = ctx.unique_name(prefix)
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "simparity-check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:PutObject", "s3:PutObjectAcl", "s3:GetBucketLocation", "s3:ListBucket"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(access_policy))

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_delivery_stream_with_retry(
    ctx, firehose, *, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs
) -> dict:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err: Optional[Exception] = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as err:
            if err.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = err
            time.sleep(interval_s)
    raise AssertionError(f"create_delivery_stream kept failing with InvalidArgumentException: {last_err}")


def _wait_for_stream_status(
    ctx, firehose, name: str, terminal_statuses: Iterable[str], timeout_s: float = 120.0, interval_s: float = 3.0
) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status in terminal_statuses:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not reach a terminal status in {timeout_s}s, last={status}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

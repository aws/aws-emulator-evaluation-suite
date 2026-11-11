"""create-stream-role-missing-trust-policy-rejected."""
from __future__ import annotations

import json
import time
from typing import Any, Iterable, Optional

from behavioral_harness import tags

CHECK = "create-stream-role-missing-trust-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream rejects an S3-destination role whose trust policy does not
    allow firehose.amazonaws.com to assume it, and never creates the stream. The same
    setup with a properly-trusted role succeeds."""
    s3 = ctx.client("s3")
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")

    bucket_name = ctx.unique_name("sim2real-behav-fhbucket-")
    _create_bucket(ctx, s3, bucket_name)
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    # Role trusts EC2, NOT firehose.amazonaws.com -> Firehose cannot assume it.
    bad_role_arn = _create_role(ctx, iam, "sim2real-behav-fhrole-bad-", "ec2.amazonaws.com", bucket_arn)

    bad_stream_name = ctx.unique_name("sim2real-behav-fhstream-bad-")
    code, msg = _error_code(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=bad_stream_name,
            S3DestinationConfiguration={"RoleARN": bad_role_arn, "BucketARN": bucket_arn},
        )
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected_msg = f"Firehose is unable to assume role {bad_role_arn}. Please check the role provided."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # Effect absent: the rejected call never created a delivery stream.
    not_found_code, not_found_msg = _error_code(lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_stream_name))
    assert not_found_code == "ResourceNotFoundException", f"expected stream absent, got {not_found_code}"
    expected_nf = f"Firehose under account {ctx.account} not found."
    assert not_found_msg == expected_nf, f"expected message {expected_nf!r}, got {not_found_msg!r}"

    # Positive control: an otherwise-identical role that DOES trust firehose.amazonaws.com succeeds.
    good_role_arn = _create_role(ctx, iam, "sim2real-behav-fhrole-good-", "firehose.amazonaws.com", bucket_arn)
    good_stream_name = ctx.unique_name("sim2real-behav-fhstream-good-")
    _create_delivery_stream_with_retry(
        ctx,
        firehose,
        DeliveryStreamName=good_stream_name,
        S3DestinationConfiguration={"RoleARN": good_role_arn, "BucketARN": bucket_arn},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: firehose.delete_delivery_stream(DeliveryStreamName=good_stream_name, AllowForceDelete=True))
    status = _wait_for_stream_status(ctx, firehose, good_stream_name, {"ACTIVE", "CREATING_FAILED"})
    assert status == "ACTIVE", f"expected positive control to reach ACTIVE, got {status}"


def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _create_bucket(ctx, s3, name: str) -> None:
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint for its own region
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
    """IAM role trust can take a while to propagate; retry the create call on the
    IAM-propagation flavor of InvalidArgumentException until it settles."""
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

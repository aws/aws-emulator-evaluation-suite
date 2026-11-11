"""firehose-role-without-trust-policy-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "firehose-role-without-trust-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["events", "firehose", "s3"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream is rejected and creates no stream when the role does not trust
    firehose.amazonaws.com, while an otherwise identical role that does trust it succeeds."""
    firehose = ctx.client("firehose")
    bucket = _create_bucket(ctx, "sim2real-fh-neg-")

    bad_role_arn = _create_role(ctx, "ec2.amazonaws.com", _s3_write_policy(bucket))
    bad_stream = ctx.unique_name("sim2real-fh-bad-")
    trust_message = _assert_rejected_for_missing_trust(
        firehose,
        deadline_s=90.0,
        DeliveryStreamName=bad_stream,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": bad_role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
    )

    expected_trust_message = f"Firehose is unable to assume role {bad_role_arn}. Please check the role provided."
    assert trust_message == expected_trust_message, (
        f"expected the trust-policy rejection message {expected_trust_message!r}, got {trust_message!r}"
    )

    # effect absent: the delivery stream was never actually created
    not_found_code, not_found_message = _error(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_stream)
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for the never-created stream {bad_stream}, "
        f"got {not_found_code!r}"
    )
    expected_not_found = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected_not_found, (
        f"expected the not-found message {expected_not_found!r}, got {not_found_message!r}"
    )

    # positive control: an otherwise-identical role that DOES trust firehose succeeds
    good_role_arn = _create_role(ctx, "firehose.amazonaws.com", _s3_write_policy(bucket))
    good_stream = ctx.unique_name("sim2real-fh-good-")
    _create_delivery_stream_with_retry(
        firehose,
        DeliveryStreamName=good_stream,
        DeliveryStreamType="DirectPut",
        ExtendedS3DestinationConfiguration={
            "RoleARN": good_role_arn,
            "BucketARN": f"arn:aws:s3:::{bucket}",
            "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
        },
    )
    ctx.on_cleanup(lambda: _delete_stream(firehose, good_stream))
    _wait_stream_active(firehose, good_stream)


# ===== helpers =====

def _error(fn) -> tuple[str, str]:
    """Call fn(); return the AWS error (Code, Message) it raised. An unexpected SUCCESS
    raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_bucket(ctx, prefix: str) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix)
    kwargs: dict[str, Any] = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        # us-east-1 is CreateBucket's implicit default region and rejects an explicit
        # LocationConstraint for it -- not a region pin, just that one API's own quirk.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    return bucket


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs})
    s3.delete_bucket(Bucket=bucket)


def _delete_stream(firehose, name: str, timeout_s: float = 180.0) -> None:
    """Delete the stream and wait until DescribeDeliveryStream reports it gone (DELETING is not gone)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name)
        while time.monotonic() < deadline:
            firehose.describe_delivery_stream(DeliveryStreamName=name)
            time.sleep(2)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    raise AssertionError(f"delivery stream {name} still exists {timeout_s:.0f}s after its delete")


def _create_role(ctx, trust_service: str, permissions: dict) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}],
    }
    resp = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = resp["Role"]["Arn"]
    policy_name = f"{role_name}-policy"
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permissions))
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, policy_name))
    return role_arn


def _delete_role(iam, role_name: str, policy_name: str) -> None:
    """The inline policy has to go before the role; one cleanup keeps that order."""
    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    iam.delete_role(RoleName=role_name)


def _s3_write_policy(bucket: str) -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["s3:PutObject", "s3:PutObjectAcl"], "Resource": f"arn:aws:s3:::{bucket}/*"},
            {"Effect": "Allow", "Action": ["s3:GetBucketLocation", "s3:ListBucket"], "Resource": f"arn:aws:s3:::{bucket}"},
        ],
    }


def _assert_rejected_for_missing_trust(firehose, *, deadline_s: float, **kwargs) -> str:
    """A role's trust policy can be unreadable to Firehose for a few seconds after IAM
    create_role returns (the same eventual-consistency window _create_delivery_stream_with_retry
    waits out for the positive control), so the first call after role creation can transiently
    read as some other error before settling on the stable, content-based rejection. Retry only
    while the observed code is NOT the expected one; the moment InvalidArgumentException is seen,
    that is the trust-policy rejection settling in, not noise -- return immediately rather than
    re-polling for the rest of the window, since the ec2.amazonaws.com principal can never become
    valid no matter how long propagation continues."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + deadline_s
    last_code: str | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(**kwargs)
            raise AssertionError(
                "create_delivery_stream unexpectedly succeeded for a role whose trust policy "
                "does not include firehose.amazonaws.com"
            )
        except ClientError as e:
            last_code = e.response["Error"]["Code"]
            if last_code == "InvalidArgumentException":
                return e.response["Error"].get("Message", "")
        time.sleep(2)
    raise AssertionError(
        f"create_delivery_stream never settled on InvalidArgumentException within {deadline_s}s "
        f"(last code={last_code})"
    )


def _create_delivery_stream_with_retry(firehose, **kwargs) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 90
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            firehose.create_delivery_stream(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] != "InvalidArgumentException":
                raise
            last_err = e
            time.sleep(2)
    raise AssertionError(f"create_delivery_stream never succeeded (IAM propagation?): {last_err}")


def _wait_stream_active(firehose, name: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        if status == "CREATING_FAILED":
            raise AssertionError(f"delivery stream {name} entered CREATING_FAILED")
        time.sleep(5)
    raise AssertionError(f"delivery stream {name} never became ACTIVE (last status={status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

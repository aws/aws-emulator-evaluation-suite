"""create-stream-role-missing-trust-policy-denied."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-role-missing-trust-policy-denied"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream is rejected, leaving no stream, when the role does not trust
    firehose.amazonaws.com. A correctly trusted role on the same bucket succeeds."""
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")
    bucket_arn = _create_bucket(ctx)

    # a role that trusts ec2, NOT firehose -- syntactically valid, wrong trust
    untrusted_role_name = ctx.unique_name("sim2real-fh-untrusted-")
    untrusted_role_arn = iam.create_role(
        RoleName=untrusted_role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "ec2.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=untrusted_role_name))
    iam.put_role_policy(
        RoleName=untrusted_role_name,
        PolicyName="s3-access",
        PolicyDocument=json.dumps(
            {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=untrusted_role_name, PolicyName="s3-access")
    )

    bad_name = ctx.unique_name("sim2real-fh-untrusted-stream-")
    code, msg = _error_code(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=bad_name,
            ExtendedS3DestinationConfiguration={"RoleARN": untrusted_role_arn, "BucketARN": bucket_arn},
        )
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected_msg = f"Firehose is unable to assume role {untrusted_role_arn}. Please check the role provided."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # effect absent: no delivery stream with the rejected name was created
    code2, msg2 = _error_code(lambda: firehose.describe_delivery_stream(DeliveryStreamName=bad_name))
    assert code2 == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code2}"
    expected_msg2 = f"Firehose under account {ctx.account} not found."
    assert msg2 == expected_msg2, f"expected message {expected_msg2!r}, got {msg2!r}"

    # positive control: a correctly-trusted role on the same bucket succeeds
    trusted_role_arn = _create_trusted_role(ctx, "firehose.amazonaws.com")
    good_name = ctx.unique_name("sim2real-fh-trusted-stream-")
    _create_stream_with_role_retry(
        firehose,
        DeliveryStreamName=good_name,
        ExtendedS3DestinationConfiguration={"RoleARN": trusted_role_arn, "BucketARN": bucket_arn},
    )
    ctx.on_cleanup(lambda: _delete_stream(firehose, good_name))
    good_desc = _wait_for_stream_active(firehose, good_name)
    assert good_desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected positive control to reach ACTIVE, got {good_desc['DeliveryStreamStatus']}"
    )


def _error_code(fn):
    """Call fn(), which must fail; return (Error.Code, Error.Message); a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _bucket_name(ctx) -> str:
    return ctx.unique_name("sim2real-fh-bkt-").lower().replace("_", "-")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _bucket_name(ctx)
    if ctx.region == "us-east-1":
        # us-east-1 is the one region where CreateBucket forbids LocationConstraint entirely.
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    return f"arn:aws:s3:::{name}"


def _create_trusted_role(ctx, trust_service: str = "firehose.amazonaws.com") -> str:
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)[
        "Role"
    ]["Arn"]
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


def _delete_stream(firehose, name: str) -> None:
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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

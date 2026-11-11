"""create-stream-nonexistent-role-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-nonexistent-role-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream with a RoleARN pointing at a non-existent IAM role is
    rejected as an invalid argument, not silently accepted and left to fail async."""
    firehose = ctx.client("firehose")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = _create_bucket(ctx)
    bogus_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-fh-noexist-role-')}"
    stream_name = ctx.unique_name("sim2real-fh-badrole-")

    code, msg = _error_code(
        lambda: firehose.create_delivery_stream(
            DeliveryStreamName=stream_name,
            S3DestinationConfiguration={
                "RoleARN": bogus_role_arn,
                "BucketARN": f"arn:aws:s3:::{bucket}",
            },
        ),
        expect_rejection_of="CreateDeliveryStream with a RoleARN for a non-existent IAM role",
    )
    assert code == "InvalidArgumentException", (
        f"expected InvalidArgumentException, got {code!r}: {msg!r}"
    )
    expected = f"Firehose is unable to assume role {bogus_role_arn}. Please check the role provided."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: no delivery stream object was ever created under this name
    not_found_code, not_found_msg = _error_code(
        lambda: firehose.describe_delivery_stream(DeliveryStreamName=stream_name),
        expect_rejection_of=f"DescribeDeliveryStream({stream_name!r}) after the rejected create",
    )
    assert not_found_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {not_found_code!r}: {not_found_msg!r}"
    )
    expected = f"Firehose under account {ctx.account} not found."
    assert not_found_msg == expected, f"expected message {expected!r}, got {not_found_msg!r}"

    # positive control: the identical shape of call with a real, assumable role succeeds
    role_arn = _create_firehose_s3_role(ctx, bucket)
    control_name = ctx.unique_name("sim2real-fh-goodrole-")
    ctx.on_cleanup(lambda: _best_effort_delete(firehose, control_name))
    desc = _create_active_stream(ctx, firehose, control_name, role_arn, bucket)
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"positive control: expected ACTIVE, got {desc['DeliveryStreamStatus']!r}"
    )


def _error_code(fn, *, expect_rejection_of):
    """Call fn(); return (Error.Code, Error.Message) on ClientError. An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"{expect_rejection_of} should be rejected but SUCCEEDED: {result!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-").lower()
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        # CreateBucketConfiguration.LocationConstraint must be omitted for us-east-1 —
        # S3 rejects the call if it is set to the bucket's own default region.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]}
    )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_firehose_s3_role(ctx, bucket_name):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "firehose.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = ctx.unique_name("sim2real-fh-policy-")
    policy_doc = {
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
                "Resource": [f"arn:aws:s3:::{bucket_name}", f"arn:aws:s3:::{bucket_name}/*"],
            }
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _wait_for_stream_status(ctx, firehose, name, target_statuses, timeout_s=180.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = firehose.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        last = desc["DeliveryStreamStatus"]
        if last in target_statuses:
            return desc
        time.sleep(3)
    raise AssertionError(f"stream {name} never reached {target_statuses}, last status={last}")


def _create_active_stream(ctx, firehose, name, role_arn, bucket_name, buffering=None):
    s3_config = {"RoleARN": role_arn, "BucketARN": f"arn:aws:s3:::{bucket_name}"}
    if buffering:
        s3_config["BufferingHints"] = buffering
    deadline = time.monotonic() + 90.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                S3DestinationConfiguration=s3_config,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            break
        except ClientError as e:
            # A freshly created IAM role/policy can lag a few seconds before Firehose
            # can successfully assume it: poll by retrying the actual create call.
            # https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
            if e.response["Error"]["Code"] == "InvalidArgumentException" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise
    return _wait_for_stream_status(ctx, firehose, name, {"ACTIVE"})


def _best_effort_delete(firehose, name):
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

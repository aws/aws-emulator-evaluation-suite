"""create-stream-conflicting-destination-configs."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-conflicting-destination-configs"
GROUP = 'overly-permissive'
SERVICES = ['firehose']

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

ACCESS_POLICY = {
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
                "kms:Decrypt",
                "kms:GenerateDataKey",
                "logs:PutLogEvents",
            ],
            "Resource": "*",
        }
    ],
}

def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of its ClientError. An unexpected
    success raises, so a target accepting what AWS refuses cannot read as a mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

def _bucket_arn(bucket_name):
    return f"arn:aws:s3:::{bucket_name}"

def _describe(ctx, name):
    return ctx.client("firehose").describe_delivery_stream(DeliveryStreamName=name)[
        "DeliveryStreamDescription"
    ]

def _delivery_role_arn(ctx):
    """Create a real IAM role Firehose can assume (validated at CreateDeliveryStream
    time, so a fabricated ARN is not usable); register its teardown."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-fh-role-")
    resp = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(TRUST_POLICY),
        Description="SimParityProbe behavioral fixture role",
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    iam.put_role_policy(
        RoleName=name,
        PolicyName="firehose-destination-access",
        PolicyDocument=json.dumps(ACCESS_POLICY),
    )

    def _teardown():
        try:
            for pn in iam.list_role_policies(RoleName=name).get("PolicyNames", []):
                try:
                    iam.delete_role_policy(RoleName=name, PolicyName=pn)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
            iam.delete_role(RoleName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_teardown)
    return resp["Role"]["Arn"]

def _make_bucket(ctx):
    """Create an S3 destination bucket and register its (empty-then-delete) teardown."""
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-firehose-dst-")
    kwargs = {"Bucket": name}
    if ctx.region and ctx.region != "us-east-1":
        # us-east-1 is the only region S3 rejects an explicit LocationConstraint for.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "sim2real-behavioral-check", "Value": CHECK}]},
    )

    def _teardown():
        try:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=name):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=name, Key=obj["Key"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_teardown)
    return name

def _default_s3_config(ctx, bucket_name):
    return {
        "RoleARN": _delivery_role_arn(ctx),
        "BucketARN": _bucket_arn(bucket_name),
        "BufferingHints": {"SizeInMBs": 1, "IntervalInSeconds": 60},
    }

def _shared_bucket(ctx):
    return _make_bucket(ctx)

def _create_with_role_propagation_retry(ctx, name, timeout_s=90.0, **kwargs):
    """Create the stream, retrying only the transient InvalidArgumentException
    ("not authorized"/"unable to assume role") seen while a new role's trust policy propagates."""
    firehose = ctx.client("firehose")
    def _cleanup():
        try:
            firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            firehose.create_delivery_stream(DeliveryStreamName=name, **kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = str(exc).lower()
            role_not_ready = code == "InvalidArgumentException" and (
                "not authorized" in msg or "unable to assume role" in msg
            )
            if role_not_ready and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise

def _wait_active(ctx, name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = _describe(ctx, name)
        status = desc["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return desc
        if status in ("CREATING_FAILED", "DELETING_FAILED"):
            raise AssertionError(f"delivery stream {name} entered {status}")
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} did not become ACTIVE within {timeout_s}s")

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream rejects a request naming more than one destination configuration. The
    same config under exactly one destination reaches ACTIVE, so the conflict causes the
    rejection."""
    bucket = _shared_bucket(ctx)
    s3_cfg = _default_s3_config(ctx, bucket)

    bad_name = ctx.unique_name("sim2real-behav-fh-conflict-dest-")
    code, message = _err(
        lambda: ctx.client("firehose").create_delivery_stream(
            DeliveryStreamName=bad_name,
            ExtendedS3DestinationConfiguration=s3_cfg,
            S3DestinationConfiguration=s3_cfg,
        )
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected = "Exactly one of S3DestinationConfiguration or ExtendedS3DestinationConfiguration must be specified."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    not_found_code, not_found_message = _err(lambda: _describe(ctx, bad_name))
    assert not_found_code == "ResourceNotFoundException", (
        f"conflicting-destination call must not create a stream, describe gave {not_found_code}"
    )
    expected = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"
    listed = ctx.client("firehose").list_delivery_streams(Limit=10000)["DeliveryStreamNames"]
    assert bad_name not in listed, "rejected stream name unexpectedly appears in ListDeliveryStreams"

    # Positive control: the identical role/bucket/buffering config, named under
    # exactly one destination parameter, is accepted and reaches ACTIVE.
    good_name = ctx.unique_name("sim2real-behav-fh-single-dest-")
    _create_with_role_propagation_retry(
        ctx,
        good_name,
        S3DestinationConfiguration=s3_cfg,
        Tags=[{"Key": "sim2real-behavioral-check", "Value": CHECK}],
    )
    desc = _wait_active(ctx, good_name)
    assert desc["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected single-destination stream to reach ACTIVE, got {desc['DeliveryStreamStatus']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

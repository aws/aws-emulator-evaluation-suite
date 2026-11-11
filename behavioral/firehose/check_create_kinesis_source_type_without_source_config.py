"""create-kinesis-source-type-without-source-config."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-kinesis-source-type-without-source-config"
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
    )
    iam.put_role_policy(
        RoleName=name,
        PolicyName="firehose-destination-access",
        PolicyDocument=json.dumps(ACCESS_POLICY),
    )
    iam.tag_role(RoleName=name, Tags=[{"Key": "sim2real:check", "Value": CHECK}])

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
    # us-east-1 is the one region S3 rejects a LocationConstraint for; not a pinned
    # resource, just the well-known CreateBucket quirk.
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real:check", "Value": CHECK}]})

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

def _create_stream_retrying(firehose, *, timeout_s=90, interval_s=5, **kwargs):
    """IAM's own eventual consistency can make a just-created role transiently
    unassumable, which Firehose also reports as InvalidArgumentException; retry on
    that specific message rather than treating it as the rejection under test."""
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return firehose.create_delivery_stream(**kwargs)
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "").lower()
            if code == "InvalidArgumentException" and ("not authorized" in msg or "access denied" in msg or "assume" in msg):
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    raise last_err

def _wait_active(ctx, name, timeout_s=120):
    firehose = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = _describe(ctx, name)["DeliveryStreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(3)
    raise AssertionError(f"delivery stream {name} never reached ACTIVE (last status={status})")

def _force_delete(ctx, name):
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream with DeliveryStreamType=KinesisStreamAsSource but no
    KinesisStreamSourceConfiguration must be rejected — the source binding is
    mandatory for that stream type (overly-permissive check)."""
    name = ctx.unique_name("sim2real-behav-fh-nosource-")
    s3_cfg = _default_s3_config(ctx, _shared_bucket(ctx))
    code, message = _err(
        lambda: ctx.client("firehose").create_delivery_stream(
            DeliveryStreamName=name,
            DeliveryStreamType="KinesisStreamAsSource",
            ExtendedS3DestinationConfiguration=s3_cfg,
        )
    )
    assert code == "InvalidArgumentException", f"expected InvalidArgumentException, got {code}"
    expected = "KinesisSourceStreamConfig is mandatory for KinesisStreamAsSource stream type."
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    not_found_code, not_found_message = _err(lambda: _describe(ctx, name))
    assert not_found_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {not_found_code}"
    expected = f"Firehose under account {ctx.account} not found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"

    # Positive control: the same role/bucket, with DeliveryStreamType left at its
    # default (DIRECT_PUT, which needs no source config) must succeed. This proves the
    # rejection above is specific to the missing KinesisStreamSourceConfiguration, not
    # a broken role, bucket or account that would reject every CreateDeliveryStream.
    control_name = ctx.unique_name("sim2real-behav-fh-nosource-ctrl-")
    _create_stream_retrying(
        ctx.client("firehose"),
        DeliveryStreamName=control_name,
        ExtendedS3DestinationConfiguration=s3_cfg,
    )
    ctx.on_cleanup(lambda: _force_delete(ctx, control_name))
    _wait_active(ctx, control_name)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

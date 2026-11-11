"""create-stream-initial-state-creating."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-stream-initial-state-creating"
GROUP = 'lifecycle'
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]}
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

def _delete_stream(ctx, name, force=True):
    try:
        ctx.client("firehose").delete_delivery_stream(
            DeliveryStreamName=name, AllowForceDelete=force
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_stream(ctx, name, bucket_name=None, **extra):
    """Create a delivery stream with a minimal ExtendedS3 destination unless the
    caller supplies their own destination kwargs. Retries while the IAM role is
    still propagating (Firehose rejects a brand-new role until it is visible)."""
    fh = ctx.client("firehose")
    if bucket_name is None and not any(
        k.endswith("DestinationConfiguration") for k in extra
    ):
        bucket_name = _make_bucket(ctx)
    kwargs = {"DeliveryStreamName": name}
    if bucket_name is not None:
        kwargs["ExtendedS3DestinationConfiguration"] = _default_s3_config(ctx, bucket_name)
    kwargs.update(extra)

    deadline = time.monotonic() + 60
    while True:
        try:
            resp = fh.create_delivery_stream(**kwargs)
            break
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
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))
    return resp

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDeliveryStream returns an ARN at once; the first describe reads the stream CREATING
    (or already ACTIVE) at VersionId 1 with no destinations-overflow flag, and the stream then
    converges to ACTIVE."""
    name = ctx.unique_name("sim2real-behav-fh-create-")
    resp = _create_stream(ctx, name)
    assert resp["DeliveryStreamARN"].endswith(f":deliverystream/{name}"), resp["DeliveryStreamARN"]

    desc = _describe(ctx, name)
    assert desc["DeliveryStreamStatus"] in ("CREATING", "ACTIVE"), (
        f"expected CREATING or ACTIVE immediately after create, got {desc['DeliveryStreamStatus']}"
    )
    assert desc["DeliveryStreamName"] == name
    assert desc["VersionId"] == "1", f"expected VersionId '1', got {desc['VersionId']}"
    assert desc["DeliveryStreamType"] == "DirectPut"
    assert desc["HasMoreDestinations"] is False
    assert "CreateTimestamp" in desc

    settled = _wait_for_terminal_status(ctx, name)
    assert settled["DeliveryStreamStatus"] == "ACTIVE", (
        f"expected the new stream to reach ACTIVE, got {settled['DeliveryStreamStatus']}"
    )


def _wait_for_terminal_status(ctx, name, timeout_s=300.0):
    """Poll DescribeDeliveryStream until the status leaves CREATING; raise on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = _describe(ctx, name)
        last = desc["DeliveryStreamStatus"]
        if last != "CREATING":
            return desc
        time.sleep(3)
    raise AssertionError(f"stream {name} still {last} after {timeout_s:.0f}s")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

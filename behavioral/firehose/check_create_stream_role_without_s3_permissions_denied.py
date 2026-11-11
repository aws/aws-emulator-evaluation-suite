"""create-stream-role-without-s3-permissions-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "create-stream-role-without-s3-permissions-denied"
GROUP = "overly-permissive"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:negative-delivery", "cap:c4", "cap:c7", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A stream whose role lacks s3:PutObject is created but never delivers to the bucket.
    A sibling stream whose role has s3:PutObject lands an object in the same bucket."""
    firehose = ctx.client("firehose")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    bucket_arn = f"arn:aws:s3:::{bucket}"
    role_noperm = _create_firehose_role(ctx, with_s3_permissions=False, bucket_arn=bucket_arn)
    role_perm = _create_firehose_role(ctx, with_s3_permissions=True, bucket_arn=bucket_arn)

    prefix_noperm = "noperm/"
    prefix_perm = "permok/"
    name_noperm = ctx.unique_name("sim2real-fh-noperm-")
    name_perm = ctx.unique_name("sim2real-fh-perm-")

    buffering = {"SizeInMBs": 1, "IntervalInSeconds": 60}

    stream_tags = [{"Key": "purpose", "Value": "behavioral-check"}]

    _create_stream_retrying(
        ctx, firehose,
        DeliveryStreamName=name_noperm,
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_noperm,
            "BucketARN": bucket_arn,
            "Prefix": prefix_noperm,
            "BufferingHints": buffering,
        },
        Tags=stream_tags,
    )
    ctx.on_cleanup(lambda: _force_delete_stream(firehose, name_noperm))

    _create_stream_retrying(
        ctx, firehose,
        DeliveryStreamName=name_perm,
        ExtendedS3DestinationConfiguration={
            "RoleARN": role_perm,
            "BucketARN": bucket_arn,
            "Prefix": prefix_perm,
            "BufferingHints": buffering,
        },
        Tags=stream_tags,
    )
    ctx.on_cleanup(lambda: _force_delete_stream(firehose, name_perm))

    _wait_stream_active(firehose, name_noperm, timeout_s=120)
    _wait_stream_active(firehose, name_perm, timeout_s=120)

    firehose.put_record(DeliveryStreamName=name_noperm, Record={"Data": b"no-perm-payload\n"})
    firehose.put_record(DeliveryStreamName=name_perm, Record={"Data": b"has-perm-payload\n"})

    # Poll both prefixes together for up to 4 minutes -- long enough for the buffering
    # interval (60s min) plus S3 delivery latency to let the permitted stream land an object.
    perm_delivered = False
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        perm_objs = s3.list_objects_v2(Bucket=bucket, Prefix=prefix_perm).get("Contents", [])
        if perm_objs:
            perm_delivered = True
            break
        time.sleep(2)

    assert perm_delivered, "positive-control stream (role WITH s3:PutObject) never delivered to S3"

    noperm_objs = s3.list_objects_v2(Bucket=bucket, Prefix=prefix_noperm).get("Contents", [])
    assert noperm_objs == [], (
        "stream wired to a role WITHOUT s3:PutObject delivered data anyway -- "
        f"found objects: {noperm_objs}"
    )


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-fh-bkt-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_firehose_role(ctx, *, with_s3_permissions: bool, bucket_arn: str) -> str:
    iam = ctx.client("iam")
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
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    if with_s3_permissions:
        policy_name = f"{role_name}-s3-access"
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": [
                    "s3:AbortMultipartUpload",
                    "s3:GetBucketLocation",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:ListBucketMultipartUploads",
                    "s3:PutObject",
                ],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }],
        }
        iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_stream_retrying(ctx, firehose, *, timeout_s: float = 90, interval_s: float = 5, **kwargs: Any):
    """CreateDeliveryStream against a just-created role can transiently fail while IAM
    propagates; retry only that specific case."""
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
    assert last_err is not None, "retry loop exited without ever calling create_delivery_stream"
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

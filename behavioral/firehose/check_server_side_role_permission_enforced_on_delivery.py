"""server-side-role-permission-enforced-on-delivery."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-role-permission-enforced-on-delivery"
GROUP = "server-side"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/APIReference/API_BufferingHints.html
@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Revoking the S3 write permission from a delivery stream's IAM role stops server-side
    delivery of subsequent records (no new S3 objects appear), even though PutRecord itself
    keeps being accepted -- the enforcement happens entirely on the server side, not the client."""
    firehose = ctx.client("firehose")
    iam = ctx.client("iam")

    bucket_name, bucket_arn = _create_bucket(ctx)
    role_name, role_arn, policy_name = _create_firehose_role(ctx, bucket_arn)
    stream_name = _create_extended_s3_stream(ctx, role_arn, bucket_arn)
    _wait_stream_active(ctx, stream_name)

    marker_a = f"payload-a-{uuid.uuid4().hex}"
    firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": marker_a.encode()})

    # Positive control: with the role intact, the record must actually reach S3 within a
    # buffering interval (BufferingHints.IntervalInSeconds=60, the documented minimum) plus
    # processing time.
    objects = _poll_until(
        lambda: _list_objects(ctx, bucket_name),
        lambda objs: len(objs) >= 1,
        timeout_s=180.0,
        interval_s=10.0,
    )
    baseline_count = len(objects)
    assert baseline_count >= 1, f"baseline delivery with a valid role never happened: {objects!r}"

    # Revoke the S3 write permission from the delivery role.
    iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)

    marker_b = f"payload-b-{uuid.uuid4().hex}"
    put_resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": marker_b.encode()})
    # PutRecord is still accepted -- ingestion is decoupled from delivery.
    assert "RecordId" in put_resp, f"PutRecord was rejected after role permission revocation: {put_resp!r}"

    # Poll for growth in object count; the invariant under test is that it never grows once the
    # role can no longer write to the bucket.
    deadline = time.monotonic() + 150.0
    grew = False
    latest_count = baseline_count
    while time.monotonic() < deadline:
        latest_count = len(_list_objects(ctx, bucket_name))
        if latest_count > baseline_count:
            grew = True
            break
        time.sleep(2)
    assert not grew, (
        f"objects were delivered to S3 ({latest_count} > {baseline_count}) after the "
        "delivery role's S3 write permission was revoked"
    )

    # The stream itself stays ACTIVE -- a delivery-side permission failure is not a
    # stream-lifecycle failure.
    status = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)[
        "DeliveryStreamDescription"
    ]["DeliveryStreamStatus"]
    assert status == "ACTIVE", f"stream left ACTIVE after a delivery-side permission failure: {status}"


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-bkt-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    # us-east-1 is S3's default region -- CreateBucket rejects an explicit
    # LocationConstraint naming it, so the constraint is omitted only there.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return name, f"arn:aws:s3:::{name}"


def _empty_and_delete_bucket(ctx, name):
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _list_objects(ctx, bucket_name):
    s3 = ctx.client("s3")
    return s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])


def _s3_write_statements(bucket_arn):
    return [{
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
    }]


def _create_firehose_role(ctx, bucket_arn, extra_statements=None):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-fh-role-")
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

    statements = _s3_write_statements(bucket_arn)
    if extra_statements:
        statements.extend(extra_statements)

    policy_name = ctx.unique_name("sim2real-behav-fh-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )

    def _cleanup_policy():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_policy)
    return role_name, role_arn, policy_name


def _create_extended_s3_stream(ctx, role_arn, bucket_arn, buffering_interval=60, buffering_size_mb=1):
    # IAM role trust propagation into Firehose is eventually consistent -- a freshly created
    # role can transiently be rejected with InvalidArgumentException ("unable to assume role")
    # even though the trust policy is correct, so retry through that window.
    firehose = ctx.client("firehose")
    name = ctx.unique_name("sim2real-behav-fh-stream-")
    dest_config = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": buffering_interval, "SizeInMBs": buffering_size_mb},
    }
    deadline = time.monotonic() + 120.0
    while True:
        try:
            firehose.create_delivery_stream(
                DeliveryStreamName=name,
                DeliveryStreamType="DirectPut",
                ExtendedS3DestinationConfiguration=dest_config,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
            break
        except ClientError as err:
            code = err.response["Error"]["Code"]
            msg = err.response["Error"].get("Message", "")
            if code == "InvalidArgumentException" and "unable to assume role" in msg.lower() and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_stream(ctx, name))
    return name


def _delete_stream(ctx, name):
    firehose = ctx.client("firehose")
    try:
        firehose.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_active(ctx, name, timeout_s: float = 180.0) -> str:
    firehose = ctx.client("firehose")

    def probe():
        return firehose.describe_delivery_stream(DeliveryStreamName=name)[
            "DeliveryStreamDescription"
        ]["DeliveryStreamStatus"]

    deadline = time.monotonic() + timeout_s
    status = probe()
    while status not in ("ACTIVE", "CREATING_FAILED") and time.monotonic() < deadline:
        time.sleep(5.0)
        status = probe()
    if status != "ACTIVE":
        raise AssertionError(f"stream did not reach ACTIVE within {timeout_s}s: {status}")
    return status


def _poll_until(probe, predicate, *, timeout_s: float = 120.0, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""tag-stream-while-creating-is-accepted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-stream-while-creating-is-accepted"
GROUP = "concurrency"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagDeliveryStream succeeds on a CREATING stream and the tag becomes visible, although
    its model lists ResourceInUseException and other mutating calls raise it while CREATING.
    """
    role_arn, bucket_arn = _setup_role_and_bucket(ctx)
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-tag-")

    _create_stream_with_retry(ctx, name, role_arn, bucket_arn)
    ctx.on_cleanup(lambda: _safe_delete_stream(ctx, name))

    # A new stream stays CREATING for tens of seconds; reading the status on both sides of
    # the tag proves it landed while the stream was transitional.
    desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    assert desc["DeliveryStreamStatus"] == "CREATING", (
        f"expected CREATING right before the tag, got {desc['DeliveryStreamStatus']}"
    )
    fh.tag_delivery_stream(
        DeliveryStreamName=name, Tags=[{"Key": "env", "Value": "creating-attempt"}]
    )
    after = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    assert after["DeliveryStreamStatus"] == "CREATING", (
        f"expected CREATING right after the tag, got {after['DeliveryStreamStatus']}"
    )

    tags_during = _wait_for_tag(ctx, name, "env", "creating-attempt", timeout_s=60.0)
    assert {"Key": "env", "Value": "creating-attempt"} in tags_during, tags_during

    _wait_for_stream_status(ctx, name, {"ACTIVE"}, timeout_s=240.0)

    # Positive control: the same call succeeds once ACTIVE.
    fh.tag_delivery_stream(DeliveryStreamName=name, Tags=[{"Key": "env", "Value": "active"}])
    tags_after = _wait_for_tag(ctx, name, "env", "active", timeout_s=60.0)
    assert {"Key": "env", "Value": "active"} in tags_after, tags_after



def _setup_role_and_bucket(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup_bucket():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup_bucket)
    bucket_arn = f"arn:aws:s3:::{bucket}"

    role_name = ctx.unique_name("sim2real-fh-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "firehose.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    policy_name = "sim2real-fh-s3-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:AbortMultipartUpload", "s3:GetBucketLocation", "s3:GetObject",
                       "s3:ListBucket", "s3:ListBucketMultipartUploads", "s3:PutObject"],
            "Resource": [bucket_arn, f"{bucket_arn}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))

    def _cleanup_role():
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return role_arn, bucket_arn


def _s3_dest_config(role_arn, bucket_arn, extra=None):
    cfg = {
        "RoleARN": role_arn,
        "BucketARN": bucket_arn,
        "BufferingHints": {"IntervalInSeconds": 60, "SizeInMBs": 5},
    }
    if extra:
        cfg.update(extra)
    return cfg


def _create_stream_with_retry(ctx, name, role_arn, bucket_arn, extra=None, attempts=4, delay_s=15.0):
    fh = ctx.client("firehose")
    cfg = _s3_dest_config(role_arn, bucket_arn, extra)
    last_err = None
    for i in range(attempts):
        try:
            fh.create_delivery_stream(DeliveryStreamName=name, ExtendedS3DestinationConfiguration=cfg)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidArgumentException" and i < attempts - 1:
                last_err = e
                time.sleep(delay_s)
                continue
            raise
    raise last_err  # pragma: no cover


def _safe_delete_stream(ctx, name):
    fh = ctx.client("firehose")
    try:
        fh.delete_delivery_stream(DeliveryStreamName=name, AllowForceDelete=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_for_tag(ctx, name, key, value, timeout_s=60.0, interval_s=3.0):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = fh.list_tags_for_delivery_stream(DeliveryStreamName=name)["Tags"]
        if {"Key": key, "Value": value} in last:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"tag {key}={value} not visible on {name} within {timeout_s}s (last={last})")


def _wait_for_stream_status(ctx, name, target_statuses, timeout_s=180.0, interval_s=5.0):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        last = desc["DeliveryStreamStatus"]
        if last in target_statuses:
            return desc
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not reach {target_statuses} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

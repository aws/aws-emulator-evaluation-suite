"""list-delivery-streams-excludes-deleted."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-delivery-streams-excludes-deleted"
GROUP = "state-machine"
SERVICES = ["firehose"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListDeliveryStreams includes an ACTIVE stream by name, and stops returning it
    once its deletion has fully completed."""
    role_arn, bucket_arn = _setup_role_and_bucket(ctx)
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-listdel-")

    _create_stream_with_retry(ctx, name, role_arn, bucket_arn)
    ctx.on_cleanup(lambda: _safe_delete_stream(ctx, name))
    _wait_for_stream_status(ctx, name, {"ACTIVE"}, timeout_s=240.0)

    names = _all_stream_names(fh)
    assert name in names, f"{name!r} missing from ListDeliveryStreams"

    fh.delete_delivery_stream(DeliveryStreamName=name)
    _wait_for_full_deletion(ctx, name, timeout_s=360.0)

    names_after = _all_stream_names(fh)
    assert name not in names_after, f"deleted stream {name!r} still listed"


def _setup_role_and_bucket(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        # us-east-1 is the one region S3's CreateBucket rejects an explicit LocationConstraint for.
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "purpose", "Value": "behavioral-check"}]})

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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
    )["Role"]["Arn"]
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
    """Bounded retry on InvalidArgumentException: a just-created IAM role has not yet
    propagated to Firehose, which rejects it as invalid until it becomes visible."""
    fh = ctx.client("firehose")
    cfg = _s3_dest_config(role_arn, bucket_arn, extra)
    last_err = None
    for i in range(attempts):
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name,
                ExtendedS3DestinationConfiguration=cfg,
                Tags=[{"Key": "purpose", "Value": "behavioral-check"}],
            )
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


def _wait_for_full_deletion(ctx, name, timeout_s=360.0, interval_s=5.0):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
            last_status = desc["DeliveryStreamStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} not fully deleted within {timeout_s}s (last status={last_status})")


def _all_stream_names(fh) -> list[str]:
    """Every delivery stream name in the region, paged through ExclusiveStartDeliveryStreamName."""
    names: list[str] = []
    kwargs: dict = {"Limit": 10000}
    while True:
        resp = fh.list_delivery_streams(**kwargs)
        names.extend(resp["DeliveryStreamNames"])
        if not resp["HasMoreDeliveryStreams"] or not resp["DeliveryStreamNames"]:
            return names
        kwargs["ExclusiveStartDeliveryStreamName"] = resp["DeliveryStreamNames"][-1]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""delete-stream-while-update-in-progress-resource-in-use."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-stream-while-update-in-progress-resource-in-use"
GROUP = "concurrency"
SERVICES = ["firehose"]
TAGS = [{"Key": "sim2real-check", "Value": CHECK}]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """While a stream is CREATING, UpdateDestination and DeleteDeliveryStream fail with
    ResourceInUseException and its exact message; once ACTIVE the identical calls succeed."""
    role_arn, bucket_arn = _setup_role_and_bucket(ctx)
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-busy-")

    _create_stream_with_retry(ctx, name, role_arn, bucket_arn)
    ctx.on_cleanup(lambda: _safe_delete_stream(ctx, name))

    # The calls are issued right after the create returns: a new stream stays CREATING for
    # tens of seconds, and the read just before them must see CREATING.
    desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    assert desc["DeliveryStreamStatus"] == "CREATING", desc["DeliveryStreamStatus"]
    dest_id = desc["Destinations"][0]["DestinationId"]

    update_code, update_message = _expect_error(lambda: fh.update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId="1",
        DestinationId=dest_id,
        ExtendedS3DestinationUpdate={"Prefix": "should-not-apply/"},
    ))
    assert update_code == "ResourceInUseException", (update_code, update_message)
    expected = f"Cannot update firehose: {name} when it is in CREATING status"
    assert update_message == expected, f"expected {expected!r}, got {update_message!r}"

    delete_code, delete_message = _expect_error(lambda: fh.delete_delivery_stream(DeliveryStreamName=name))
    assert delete_code == "ResourceInUseException", (delete_code, delete_message)
    expected = f"Firehose {name} under account {ctx.account} cannot be deleted in CREATING state"
    assert delete_message == expected, f"expected {expected!r}, got {delete_message!r}"

    # Effect absent: the stream still exists, is still CREATING/ACTIVE (not deleted), and its
    # version was not mutated by the rejected update.
    still_there = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    assert still_there["DeliveryStreamStatus"] in ("CREATING", "ACTIVE")
    assert still_there["VersionId"] == "1"

    active = _wait_for_stream_status(ctx, name, {"ACTIVE"}, timeout_s=240.0)
    assert active["VersionId"] == "1"
    fh.update_destination(
        DeliveryStreamName=name,
        CurrentDeliveryStreamVersionId="1",
        DestinationId=dest_id,
        ExtendedS3DestinationUpdate={"Prefix": "now-allowed/"},
    )
    updated = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    assert updated["VersionId"] == "2"
    assert updated["Destinations"][0]["ExtendedS3DestinationDescription"]["Prefix"] == "now-allowed/"

    # The identical delete call — rejected above while CREATING — also now succeeds.
    fh.delete_delivery_stream(DeliveryStreamName=name)
    gone_code, gone_message = _wait_for_not_found(ctx, name, timeout_s=300.0)
    assert gone_code == "ResourceNotFoundException", gone_code
    expected = f"Firehose under account {ctx.account} not found."
    assert gone_message == expected, f"expected {expected!r}, got {gone_message!r}"


def _expect_error(fn):
    """Call fn(), which must fail; return (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _setup_role_and_bucket(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    # us-east-1 is the one region S3 rejects as an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": TAGS})

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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=TAGS
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
    fh = ctx.client("firehose")
    cfg = _s3_dest_config(role_arn, bucket_arn, extra)
    last_err = None
    for i in range(attempts):
        try:
            fh.create_delivery_stream(
                DeliveryStreamName=name, ExtendedS3DestinationConfiguration=cfg, Tags=TAGS
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


def _wait_for_not_found(ctx, name, timeout_s=180.0, interval_s=5.0):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        try:
            last_status = fh.describe_delivery_stream(DeliveryStreamName=name)[
                "DeliveryStreamDescription"]["DeliveryStreamStatus"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return e.response["Error"]["Code"], e.response["Error"].get("Message")
            last_status = f"{e.response['Error']['Code']}: {e.response['Error'].get('Message')}"
        time.sleep(interval_s)
    raise AssertionError(f"stream {name} did not become not-found within {timeout_s}s (last={last_status})")


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

"""stop-encryption-while-update-in-progress-resource-in-use."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-encryption-while-update-in-progress-resource-in-use"
GROUP = "concurrency"
SERVICES = ["firehose"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopDeliveryStreamEncryption while a prior Start is still ENABLING is rejected with
    ResourceInUseException (Firehose serializes encryption toggles); once ENABLED, the same stop
    succeeds and the status goes through DISABLING to DISABLED."""
    role_arn, bucket_arn = _setup_role_and_bucket(ctx)
    fh = ctx.client("firehose")
    name = ctx.unique_name("sim2real-fh-sse-")

    _create_stream_with_retry(ctx, name, role_arn, bucket_arn)
    ctx.on_cleanup(lambda: _safe_delete_stream(ctx, name))
    _wait_for_stream_status(ctx, name, {"ACTIVE"}, timeout_s=240.0)

    fh.start_delivery_stream_encryption(DeliveryStreamName=name)

    # Fire the stop as fast as possible after start, to land inside the ENABLING window.
    code, message = _expect_error(lambda: fh.stop_delivery_stream_encryption(DeliveryStreamName=name))
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}: {message!r}"
    expected = f"Cannot disable encryption on firehose: {name} when encryption is in ENABLING status"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: encryption is progressing toward ENABLED, not reverted.
    desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
    enc_status = desc["DeliveryStreamEncryptionConfiguration"]["Status"]
    assert enc_status in ("ENABLING", "ENABLED"), (
        f"expected ENABLING or ENABLED (rejected stop must not revert progress), got {enc_status}"
    )
    enabled = _wait_for_encryption_status(ctx, name, {"ENABLED"}, timeout_s=240.0)
    assert enabled == "ENABLED", f"expected ENABLED, got {enabled}"

    # Positive control: once ENABLED, stop succeeds and encryption settles at DISABLED.
    fh.stop_delivery_stream_encryption(DeliveryStreamName=name)
    final = _wait_for_encryption_status(ctx, name, {"DISABLED"}, timeout_s=240.0)
    assert final == "DISABLED", f"expected DISABLED, got {final}"


def _expect_error(fn):
    """Call fn(), which must fail; return (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _setup_role_and_bucket(ctx):
    s3 = ctx.client("s3")
    iam = ctx.client("iam")

    bucket = ctx.unique_name("sim2real-fh-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
                DeliveryStreamName=name,
                ExtendedS3DestinationConfiguration=cfg,
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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


def _wait_for_encryption_status(ctx, name, target_statuses, timeout_s=240.0, interval_s=5.0):
    fh = ctx.client("firehose")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = fh.describe_delivery_stream(DeliveryStreamName=name)["DeliveryStreamDescription"]
        last = desc["DeliveryStreamEncryptionConfiguration"]["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"encryption status for {name} did not reach {target_statuses} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

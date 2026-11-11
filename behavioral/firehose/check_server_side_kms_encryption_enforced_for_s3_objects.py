"""server-side-kms-encryption-enforced-for-s3-objects."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "server-side-kms-encryption-enforced-for-s3-objects"
GROUP = "server-side"
SERVICES = ["firehose"]


# timing:real-time — buffer: 60 s https://docs.aws.amazon.com/firehose/latest/dev/buffering-hints.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:eventing", "concern:representation", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """StartDeliveryStreamEncryption with a customer-managed key reaches ENABLED with that key,
    a PutRecord payload is still delivered to S3, and StopDeliveryStreamEncryption reaches DISABLED.
    """
    firehose = ctx.client("firehose")
    kms = ctx.client("kms")

    bucket_name, bucket_arn = _create_bucket(ctx)

    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-fh-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )
    key_id = key["KeyMetadata"]["KeyId"]
    key_arn = key["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    kms_statement = {
        "Effect": "Allow",
        "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant"],
        "Resource": key_arn,
    }
    _role_name, role_arn, _policy_name = _create_firehose_role(ctx, bucket_arn, extra_statements=[kms_statement])

    stream_name = _create_extended_s3_stream(ctx, role_arn, bucket_arn)
    _wait_stream_active(ctx, stream_name)

    pre_desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
    pre_status = pre_desc.get("DeliveryStreamEncryptionConfiguration", {}).get("Status")
    assert pre_status in (None, "DISABLED"), f"unexpected pre-enable encryption status: {pre_status}"

    firehose.start_delivery_stream_encryption(
        DeliveryStreamName=stream_name,
        DeliveryStreamEncryptionConfigurationInput={"KeyARN": key_arn, "KeyType": "CUSTOMER_MANAGED_CMK"},
    )

    def probe_enc():
        desc = firehose.describe_delivery_stream(DeliveryStreamName=stream_name)["DeliveryStreamDescription"]
        return desc.get("DeliveryStreamEncryptionConfiguration", {})

    enc_config = _poll_until(
        probe_enc, lambda c: c.get("Status") in ("ENABLED", "ENABLING_FAILED"), timeout_s=120.0, interval_s=5.0
    )
    assert enc_config.get("Status") == "ENABLED", f"encryption did not reach ENABLED: {enc_config}"
    assert enc_config.get("KeyType") == "CUSTOMER_MANAGED_CMK"
    assert key_id in enc_config.get("KeyARN", ""), f"unexpected KeyARN in server state: {enc_config}"

    marker = f"kms-payload-{uuid.uuid4().hex}"
    put_resp = firehose.put_record(DeliveryStreamName=stream_name, Record={"Data": marker.encode()})
    assert "RecordId" in put_resp

    # SSE covers Firehose's interim storage only; S3 object encryption is the bucket's setting.
    delivered = _poll_until(
        lambda: _marker_delivered(ctx, bucket_name, marker),
        lambda found: found,
        timeout_s=180.0,
        interval_s=10.0,
    )
    assert delivered, f"marker {marker!r} never landed in bucket {bucket_name} once CMK encryption was enabled"

    firehose.stop_delivery_stream_encryption(DeliveryStreamName=stream_name)
    stop_config = _poll_until(
        probe_enc, lambda c: c.get("Status") in ("DISABLED", "DISABLING_FAILED"), timeout_s=120.0, interval_s=5.0
    )
    assert stop_config.get("Status") == "DISABLED", f"encryption did not reach DISABLED: {stop_config}"



def _create_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-fh-bkt-").lower().replace("_", "-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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


def _marker_delivered(ctx, bucket_name, marker):
    s3 = ctx.client("s3")
    needle = marker.encode()
    for obj in _list_objects(ctx, bucket_name):
        body = s3.get_object(Bucket=bucket_name, Key=obj["Key"])["Body"].read()
        if needle in body:
            return True
    return False


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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    statements = [{
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
    if extra_statements:
        statements.extend(extra_statements)

    policy_name = ctx.unique_name("sim2real-behav-fh-pol-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_name, role_arn, policy_name


def _create_extended_s3_stream(ctx, role_arn, bucket_arn, buffering_interval=60, buffering_size_mb=1):
    # A fresh IAM role can be rejected with InvalidArgumentException until it propagates.
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
                Tags=[{"Key": "sim2real", "Value": CHECK}],
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

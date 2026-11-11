"""create-channel-invalid-kms-key-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-channel-invalid-kms-key-denied"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel with a KMS key whose policy denies data-key use fails with a
    ValidationException naming KMS and creates no channel; the same request with an accessible
    key reaches ACTIVE."""
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    s3 = ctx.client("s3")
    account = sts.get_caller_identity()["Account"]

    stream_name = ctx.unique_name("sim2real-behav-kmssrc-")
    kinesis.create_stream(StreamName=stream_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, stream_name)

    bucket = ctx.unique_name("sim2real-behav-kmsdest-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    bucket_arn = f"arn:aws:s3:::{bucket}"

    role_name = ctx.unique_name("sim2real-behav-kmsrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "kinesis.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:kinesis:{ctx.region}:{account}:channel/*"},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:ListBucket", "s3:ListBucketMultipartUploads"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:CreateMultipartUpload",
                    "s3:UploadPart",
                    "s3:CompleteMultipartUpload",
                    "s3:ListMultipartUploads",
                    "s3:ListMultipartUploadParts",
                ],
                "Resource": [f"{bucket_arn}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    }
    policy_name = "sim2real-behav-inline-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    denied_key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "DenyEveryoneDataKeyUse",
                "Effect": "Deny",
                "Principal": "*",
                "Action": ["kms:GenerateDataKey*", "kms:Decrypt", "kms:Encrypt", "kms:DescribeKey"],
                "Resource": "*",
            },
        ],
    }
    denied_key_id = kms.create_key(
        Policy=json.dumps(denied_key_policy), Description="sim2real-behav-denied-key"
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=denied_key_id, PendingWindowInDays=7))

    normal_key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }
    normal_key_id = kms.create_key(
        Policy=json.dumps(normal_key_policy), Description="sim2real-behav-normal-key"
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=normal_key_id, PendingWindowInDays=7))

    denied_channel_name = ctx.unique_name("sim2real-behav-chdenied-")
    arn, code = _create_channel_polling(
        ctx, denied_channel_name, role_arn, stream_arn, account, bucket_arn, denied_key_id
    )
    if arn is not None:
        # An unexpected success must not leak: register cleanup before the assert can
        # raise and abandon the resource.
        ctx.on_cleanup(lambda arn=arn: kinesis.delete_channel(ChannelARN=arn))
    assert arn is None, f"channel with a denied KMS key should not have been created (got {arn})"
    # KMS-key access is validated synchronously as a ValidationException, distinct from the
    # AccessDeniedException used for IAM role-assumption failures.
    assert code is not None and code.startswith("ValidationException") and "KMS" in code, code

    names = {c["ChannelName"] for c in kinesis.list_channels().get("ChannelSummaries", [])}
    assert denied_channel_name not in names, "channel with denied KMS key should not exist"

    ok_channel_name = ctx.unique_name("sim2real-behav-chok-")
    ok_arn, ok_code = _create_channel_polling(
        ctx, ok_channel_name, role_arn, stream_arn, account, bucket_arn, normal_key_id
    )
    assert ok_arn is not None, f"CreateChannel with a normal KMS key should have succeeded: {ok_code}"
    ctx.on_cleanup(lambda: kinesis.delete_channel(ChannelARN=ok_arn))
    final = _wait_channel_status(ctx, ok_arn, {"ACTIVE", "FAILED"})
    assert final["ChannelStatus"] == "ACTIVE", final.get("ChannelStatusReason")


def _error_code(exc):
    resp = getattr(exc, "response", None)
    if resp is None:
        return None
    return resp.get("Error", {}).get("Code")


def _error_message(exc):
    resp = getattr(exc, "response", None)
    if resp is None:
        return str(exc)
    return resp.get("Error", {}).get("Message")


def _create_channel_polling(ctx, channel_name, role_arn, stream_arn, account, bucket_arn, key_id, timeout_s=90.0):
    """Retry CreateChannel only on IAM propagation errors (AccessDeniedException or "unable to
    assume the service execution role"); a KMS access denial is terminal and returned."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_code = None
    last_message = None
    while True:
        try:
            resp = kinesis.create_channel(
                ChannelName=channel_name,
                ServiceExecutionRoleARN=role_arn,
                StreamConfigurationList=[
                    {"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}
                ],
                S3DestinationConfiguration={
                    "DataFreshnessInSeconds": 300,
                    "StorageConfiguration": {
                        "BucketARN": bucket_arn,
                        "ExpectedBucketOwner": account,
                        "CompressionType": "NONE",
                    },
                },
                EncryptionConfiguration={"EncryptionType": "KMS", "KeyId": key_id},
            )
            return resp["ChannelDescription"]["ChannelARN"], None
        except Exception as exc:  # noqa: BLE001
            last_code = _error_code(exc)
            last_message = _error_message(exc)
            transient = last_code == "AccessDeniedException" or (
                last_code == "ValidationException"
                and last_message
                and "assume" in last_message.lower()
            )
            if transient and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return None, f"{last_code}: {last_message}"



def _wait_stream_active(ctx, name, timeout_s=120.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE")


def _wait_channel_status(ctx, channel_arn, terminal_statuses, timeout_s=120.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
        if desc["ChannelStatus"] in terminal_statuses:
            return desc
        time.sleep(3)
    raise AssertionError(f"channel {channel_arn} never reached {terminal_statuses}, last={desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""create-channel-kms-access-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-channel-kms-access-denied"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel with a KMS key whose policy denies the execution role fails with the exact
    ValidationException and creates no channel; once the key policy allows the role, the same
    encrypted configuration succeeds and reaches ACTIVE."""
    kinesis = ctx.client("kinesis")
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    identity = sts.get_caller_identity()
    account_id = identity["Account"]


    _stream_name, stream_arn = _create_stream(ctx)
    # A second stream for the restored channel: a stream accepts only one S3-destination channel,
    # and stream_arn already carries the control channel.
    _stream_name2, stream_arn2 = _create_stream(ctx)
    role_arn, s3_dest = _channel_dest_and_role(ctx, account_id)
    stream_config = [{"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}]

    # An unencrypted control channel proves the new role is assumable first, so the later denial
    # can only be the KMS deny, not IAM propagation lag.
    control_name = ctx.unique_name("sim2real-behav-ch-ok-")
    created = _create_channel_with_retry(
        kinesis,
        ChannelName=control_name,
        ServiceExecutionRoleARN=role_arn,
        StreamConfigurationList=stream_config,
        S3DestinationConfiguration=s3_dest,
    )
    channel_arn = created["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: kinesis.delete_channel(ChannelARN=channel_arn))
    described = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
    assert described["ChannelName"] == control_name, (
        f"expected describe_channel to name the control channel {control_name!r}, "
        f"got {described['ChannelName']!r}"
    )

    policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRootFullAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "DenyExecutionRoleUse",
                    "Effect": "Deny",
                    "Principal": {"AWS": role_arn},
                    "Action": [
                        "kms:DescribeKey",
                        "kms:GenerateDataKey",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:Decrypt",
                        "kms:Encrypt",
                        "kms:CreateGrant",
                    ],
                    "Resource": "*",
                },
            ],
        }
    )
    key_meta = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kchkey-"),
        Policy=policy,
    )["KeyMetadata"]
    key_id = key_meta["KeyId"]
    key_arn = key_meta["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    denied_name = ctx.unique_name("sim2real-behav-ch-denied-")
    code, message = _refusal(
        lambda: kinesis.create_channel(
            ChannelName=denied_name,
            ServiceExecutionRoleARN=role_arn,
            StreamConfigurationList=stream_config,
            S3DestinationConfiguration=s3_dest,
            EncryptionConfiguration={"EncryptionType": "KMS", "KeyId": key_arn},
        )
    )
    # The KMS access failure surfaces as ValidationException, not the documented
    # KMSAccessDeniedException.
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "The service execution role is not authorized to access the KMS key specified in "
        "EncryptionConfiguration.KeyId. Verify that the role's IAM policy and KMS key policy "
        "grants kms:Decrypt and kms:GenerateDataKey permissions."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    listed = kinesis.list_channels(StreamFilter=[{"StreamARN": stream_arn}], MaxResults=100)
    names = [c["ChannelName"] for c in listed.get("ChannelSummaries", [])]
    assert denied_name not in names, "no channel must be created when the KMS key is inaccessible"
    assert names == [control_name], "only the earlier control channel should exist for this stream"

    # Only the key policy changes (plus a fresh name, to avoid throttling an identical request), so
    # a success proves the KMS deny, not the stream/role/bucket wiring, blocked the earlier call.
    restored_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AllowRootFullAccess",
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                    "Action": "kms:*",
                    "Resource": "*",
                },
                {
                    "Sid": "AllowExecutionRoleUse",
                    "Effect": "Allow",
                    "Principal": {"AWS": role_arn},
                    "Action": [
                        "kms:DescribeKey",
                        "kms:GenerateDataKey",
                        "kms:GenerateDataKeyWithoutPlaintext",
                        "kms:Decrypt",
                        "kms:Encrypt",
                        "kms:CreateGrant",
                    ],
                    "Resource": "*",
                },
            ],
        }
    )
    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=restored_policy)

    restored_stream_config = [
        {"StreamARN": stream_arn2, "RecordConfiguration": {"RecordFormatType": "JSON"}}
    ]
    restored_name = ctx.unique_name("sim2real-behav-ch-restored-")
    restored = _create_channel_with_retry(
        kinesis,
        ChannelName=restored_name,
        ServiceExecutionRoleARN=role_arn,
        StreamConfigurationList=restored_stream_config,
        S3DestinationConfiguration=s3_dest,
        EncryptionConfiguration={"EncryptionType": "KMS", "KeyId": key_arn},
    )
    restored_arn = restored["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: kinesis.delete_channel(ChannelARN=restored_arn))
    restored_status = _wait_channel_status(kinesis, restored_arn)
    assert restored_status == "ACTIVE", f"restored channel never reached ACTIVE, got {restored_status!r}"

    listed_after = kinesis.list_channels(StreamFilter=[{"StreamARN": stream_arn2}], MaxResults=100)
    names_after = {c["ChannelName"] for c in listed_after.get("ChannelSummaries", [])}
    assert names_after == {restored_name}, (
        f"expected only the restored channel on the second stream, got {names_after!r}"
    )


def _refusal(fn):
    """Error code and message of a call that MUST be refused. A success is a failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")




def _wait_stream_active(kinesis, stream_name, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]["StreamStatus"]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {stream_name} never became ACTIVE within {timeout_s}s")


def _create_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kch-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


def _wait_channel_status(kinesis, channel_arn, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]["ChannelStatus"]
        if status in ("ACTIVE", "FAILED"):
            return status
        time.sleep(3)
    raise AssertionError(f"channel {channel_arn} stuck in status {status!r} after {timeout_s}s")


def _channel_dest_and_role(ctx, account_id):
    """Create an assumable service execution role with S3 delivery rights and a destination bucket.

    CreateChannel checks that it can assume ServiceExecutionRoleARN before validating anything else.
    """
    iam = ctx.client("iam")
    region = ctx.client("kinesis").meta.region_name
    role_name = ctx.unique_name("sim2real-behav-role-")
    bucket_name = ctx.unique_name("sim2real-behav-bkt-").lower()
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "kinesis.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account_id},
                        "ArnLike": {"aws:SourceArn": f"arn:aws:kinesis:{region}:{account_id}:channel/*"},
                    },
                }
            ],
        }
    )
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    s3 = ctx.client("s3")
    if region == "us-east-1":
        # us-east-1 is the one region where S3 rejects an explicit LocationConstraint.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, bucket_name))

    permission_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:ListBucket",
                        "s3:ListBucketMultipartUploads",
                        "s3:PutObject",
                        "s3:CreateMultipartUpload",
                        "s3:UploadPart",
                        "s3:CompleteMultipartUpload",
                        "s3:ListMultipartUploads",
                        "s3:ListMultipartUploadParts",
                    ],
                    "Resource": [bucket_arn, f"{bucket_arn}/*"],
                }
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-behav-delivery", PolicyDocument=permission_policy)

    s3_dest = {
        "StorageConfiguration": {
            "BucketARN": bucket_arn,
            "ExpectedBucketOwner": account_id,
            "CompressionType": "NONE",
        }
    }
    return role_arn, s3_dest


def _delete_role(iam, role_name):
    try:
        for pol in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_bucket(s3, bucket_name):
    try:
        for obj in s3.list_objects_v2(Bucket=bucket_name).get("Contents", []):
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_channel_with_retry(kinesis, timeout_s=90.0, **kwargs):
    """Retry CreateChannel while it reports the transient "Unable to assume the service execution
    role" ValidationException, since a new IAM role is not immediately assumable."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.create_channel(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            exc.response["Error"].get("Message", "")
            if code in ("ValidationException", "LimitExceededException") and time.monotonic() < deadline:
                time.sleep(3)
                continue

            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


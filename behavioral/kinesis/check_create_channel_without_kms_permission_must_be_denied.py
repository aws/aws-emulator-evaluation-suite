"""create-channel-without-kms-permission-must-be-denied."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "create-channel-without-kms-permission-must-be-denied"
GROUP = "overly-permissive"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel with a KMS key the execution role has no kms:GenerateDataKey on fails with the
    exact ValidationException and creates no channel; after granting the permission the same
    configuration succeeds and reaches ACTIVE."""
    kinesis = ctx.client("kinesis")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # CreateChannel supports only on-demand streams. The granted channel lands on a second stream,
    # clear of the "deliveries per stream" quota (2, not adjustable) the denied attempts may touch.
    stream_name = ctx.unique_name("sim2real-behav-kinesis-chstream-")
    kinesis.create_stream(
        StreamName=stream_name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    stream_name2 = ctx.unique_name("sim2real-behav-kinesis-chstream2-")
    kinesis.create_stream(
        StreamName=stream_name2,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name2, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, stream_name)
    stream_arn2 = _wait_stream_active(ctx, stream_name2)

    bucket_name = ctx.unique_name("sim2real-behav-kinesis-chbucket-")
    _create_bucket(ctx, bucket_name)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    # The default key policy delegates authorization to each principal's IAM identity policy.
    key = kms.create_key(
        Description=ctx.unique_name("sim2real-behav-kinesis-key-"),
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]
    key_id = key["KeyId"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # The execution role starts with S3 delivery permissions and deliberately no KMS permissions.
    role_name = ctx.unique_name("sim2real-behav-kinesis-chrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "kinesis.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:kinesis:{ctx.region}:{account_id}:channel/*"},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    exec_policy = {
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
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="exec-policy", PolicyDocument=json.dumps(exec_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="exec-policy"))

    s3_dest = {
        "StorageConfiguration": {
            "BucketARN": bucket_arn,
            "CompressionType": "NONE",
            "ExpectedBucketOwner": account_id,
        },
    }
    stream_config = [
        {"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "STRING"}}
    ]

    # An unencrypted control channel proves the role is assumable first, so the later denial can
    # only mean the missing KMS permission, not IAM propagation lag.
    control_name = ctx.unique_name("sim2real-behav-kinesis-ch-ok-")
    control = _create_channel_with_retry(
        ctx,
        ChannelName=control_name,
        ServiceExecutionRoleARN=role_arn,
        StreamConfigurationList=stream_config,
        S3DestinationConfiguration=s3_dest,
        Tags={"sim2real": CHECK},
    )
    control_arn = control["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: kinesis.delete_channel(ChannelARN=control_arn))

    channel_name = ctx.unique_name("sim2real-behav-kinesis-channel-")
    channel_kwargs = dict(
        ChannelName=channel_name,
        ServiceExecutionRoleARN=role_arn,
        StreamConfigurationList=stream_config,
        EncryptionConfiguration={"EncryptionType": "KMS", "KeyId": key_arn},
        S3DestinationConfiguration=s3_dest,
        Tags={"sim2real": CHECK},
    )

    # The KMS access failure surfaces as ValidationException, not the documented
    # KMSAccessDeniedException; the short retry only absorbs residual IAM-propagation noise.
    code, message = _wait_for_expected_denial(
        ctx, kinesis, channel_kwargs, expected_code="ValidationException", timeout_s=30.0
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "The service execution role is not authorized to access the KMS key specified in "
        "EncryptionConfiguration.KeyId. Verify that the role's IAM policy and KMS key policy "
        "grants kms:Decrypt and kms:GenerateDataKey permissions."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listed = kinesis.list_channels(StreamFilter=[{"StreamARN": stream_arn}], MaxResults=100)
    names = [c["ChannelName"] for c in listed.get("ChannelSummaries", [])]
    assert channel_name not in names, (
        f"channel {channel_name} must not exist after a KMS-permission-denied CreateChannel, "
        f"got {names}"
    )
    assert names == [control_name], (
        f"only the earlier control channel should exist for this stream, got {names}"
    )

    # A fresh name avoids throttling on retrying an identical CreateChannel request.
    kms_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["kms:GenerateDataKey", "kms:Decrypt", "kms:DescribeKey"],
                "Resource": key_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="kms-policy", PolicyDocument=json.dumps(kms_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="kms-policy"))
    success_name = ctx.unique_name("sim2real-behav-kinesis-channel-ok-")
    channel_kwargs["ChannelName"] = success_name
    channel_kwargs["StreamConfigurationList"] = [
        {"StreamARN": stream_arn2, "RecordConfiguration": {"RecordFormatType": "STRING"}}
    ]
    channel_arn = _wait_for_create_channel_success(ctx, kinesis, channel_kwargs, timeout_s=90.0)
    ctx.on_cleanup(lambda: kinesis.delete_channel(ChannelARN=channel_arn))
    status = _wait_channel_status(ctx, channel_arn, timeout_s=90.0)
    assert status == "ACTIVE", (
        f"channel never reached ACTIVE after granting kms:GenerateDataKey, got {status!r}"
    )


def _create_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
    )


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    resp = s3.list_objects_v2(Bucket=bucket_name)
    for obj in resp.get("Contents", []):
        s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket_name)


def _create_channel_with_retry(ctx, timeout_s=60.0, **kwargs):
    """Retry CreateChannel while it reports the transient "Unable to assume the service execution
    role" ValidationException or the account-wide 5-TPS control-plane throttle."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.create_channel(**kwargs)
        except Exception as exc:
            response = getattr(exc, "response", None)
            if response is None:
                raise
            code = response["Error"]["Code"]
            if code in ("ValidationException", "LimitExceededException") and time.monotonic() < deadline:
                time.sleep(8 if code == "LimitExceededException" else 4)
                continue
            raise


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 60.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE")


def _wait_for_expected_denial(ctx, kinesis, kwargs, expected_code: str, timeout_s: float = 30.0):
    """Retry CreateChannel until it is refused with ``expected_code``; return (code, message)."""
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            resp = kinesis.create_channel(**kwargs)
        except Exception as exc:  # botocore.exceptions.ClientError
            response = getattr(exc, "response", None)
            if response is None:
                raise
            code = response["Error"]["Code"]
            if code == expected_code:
                return code, response["Error"].get("Message")
            last_code = code
            # tolerate transient IAM role / PassRole propagation errors, and the shared
            # 5-TPS account-wide control-plane throttle, while retrying
            time.sleep(8 if code == "LimitExceededException" else 4)
            continue
        arn = resp["ChannelDescription"]["ChannelARN"]
        ctx.on_cleanup(lambda a=arn: kinesis.delete_channel(ChannelARN=a))
        raise AssertionError("create_channel unexpectedly succeeded while the role lacked KMS permission")
    raise AssertionError(f"expected {expected_code}, last observed {last_code!r}")


def _wait_for_create_channel_success(ctx, kinesis, kwargs, timeout_s: float = 90.0) -> str:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            return kinesis.create_channel(**kwargs)["ChannelDescription"]["ChannelARN"]
        except Exception as exc:  # botocore.exceptions.ClientError
            response = getattr(exc, "response", None)
            if response is None:
                raise
            last_code = response["Error"]["Code"]
            # the account-wide 5-TPS control-plane throttle needs a longer back-off than
            # ordinary IAM-propagation retries
            time.sleep(8 if last_code == "LimitExceededException" else 4)
    raise AssertionError(f"create_channel never succeeded after granting kms:GenerateDataKey, last error {last_code!r}")



def _wait_channel_status(ctx, channel_arn: str, timeout_s: float = 90.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]["ChannelStatus"]
        if status in ("ACTIVE", "FAILED"):
            return status
        time.sleep(3)
    raise AssertionError(f"channel {channel_arn} stuck in status {status!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

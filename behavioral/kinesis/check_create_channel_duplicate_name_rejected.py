"""create-channel-duplicate-name-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-channel-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateChannel reusing an in-use ChannelName is rejected with the exact
    ResourceInUseException, the original channel's role is not overwritten, and a channel with a
    unique name still succeeds."""
    kinesis = ctx.client("kinesis")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    _stream_name, stream_arn = _create_stream(ctx)
    role_arn_1, s3_dest_1 = _channel_dest_and_role(ctx, account_id)
    role_arn_2, s3_dest_2 = _channel_dest_and_role(ctx, account_id)
    stream_config = [{"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}]

    shared_name = ctx.unique_name("sim2real-behav-ch-dup-")
    created = _create_channel_with_retry(
        kinesis,
        ChannelName=shared_name,
        ServiceExecutionRoleARN=role_arn_1,
        StreamConfigurationList=stream_config,
        S3DestinationConfiguration=s3_dest_1,
    )
    channel_arn = created["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: kinesis.delete_channel(ChannelARN=channel_arn))

    code, message = _refusal(
        lambda: kinesis.create_channel(
            ChannelName=shared_name,
            ServiceExecutionRoleARN=role_arn_1,
            StreamConfigurationList=stream_config,
            S3DestinationConfiguration=s3_dest_1,
        )
    )
    assert code == "ResourceInUseException", f"expected ResourceInUseException, got {code}"
    expected = f"Channel {shared_name} under account {ctx.account} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    described = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
    assert (
        described["ServiceExecutionRoleARN"] == role_arn_1
    ), "the duplicate-name create must not overwrite the existing channel's configuration"

    other_name = ctx.unique_name("sim2real-behav-ch-other-")
    _other_stream_name, other_stream_arn = _create_stream(ctx)
    other_stream_config = [
        {"StreamARN": other_stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}
    ]
    created_2 = _create_channel_with_retry(
        kinesis,
        ChannelName=other_name,
        ServiceExecutionRoleARN=role_arn_2,
        StreamConfigurationList=other_stream_config,
        S3DestinationConfiguration=s3_dest_2,
    )

    channel_arn_2 = created_2["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: kinesis.delete_channel(ChannelARN=channel_arn_2))
    described_2 = kinesis.describe_channel(ChannelARN=channel_arn_2)["ChannelDescription"]
    assert described_2["ChannelName"] == other_name, (
        f"expected the distinct-name channel to be named {other_name!r}, "
        f"got {described_2['ChannelName']!r}"
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
        Tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


def _channel_dest_and_role(ctx, account_id):
    """Create an assumable service execution role with S3 delivery rights and a destination bucket.

    CreateChannel checks that it can assume ServiceExecutionRoleARN before validating anything else.
    """
    import json

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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust_policy,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    s3 = ctx.client("s3")
    # us-east-1 is the only region where S3 rejects an explicit LocationConstraint
    # on CreateBucket; this branches on API shape, not on pinning the check to a region.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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

    kwargs.setdefault("Tags", {"sim2real": CHECK})
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

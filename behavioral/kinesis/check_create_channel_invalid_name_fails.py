"""create-channel-invalid-name-fails."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-channel-invalid-name-fails"
GROUP = "error-semantics"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel with a malformed ChannelName (space/'!' chars, violating the documented
    `[a-zA-Z0-9_.-]+` pattern) is rejected with ValidationException and no channel is ever
    created, while a syntactically valid name (otherwise identical request) succeeds."""
    kinesis = ctx.client("kinesis")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    _stream_name, stream_arn = _create_stream(ctx)
    role_arn, s3_dest = _channel_dest_and_role(ctx, account_id)
    stream_config = [{"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}]

    bad_name = "bad channel name!!"
    code, message = _error_code(
        lambda: _create_channel_with_retry(
            kinesis,
            ChannelName=bad_name,
            ServiceExecutionRoleARN=role_arn,
            StreamConfigurationList=stream_config,
            S3DestinationConfiguration=s3_dest,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value at 'channelName' failed to satisfy constraint: "
        "Member must satisfy regular expression pattern: [a-zA-Z0-9_.-]+"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"


    listed = kinesis.list_channels(StreamFilter=[{"StreamARN": stream_arn}], MaxResults=100)
    names = [c["ChannelName"] for c in listed.get("ChannelSummaries", [])]
    assert bad_name not in names, "a channel with a malformed name must never be created"
    assert names == [], "no channel should exist for this stream after the rejected create"

    good_name = ctx.unique_name("sim2real-behav-ch-")
    created = _create_channel_with_retry(
        kinesis,
        ChannelName=good_name,
        ServiceExecutionRoleARN=role_arn,
        StreamConfigurationList=stream_config,
        S3DestinationConfiguration=s3_dest,
    )
    channel_arn = created["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: kinesis.delete_channel(ChannelARN=channel_arn))
    described = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
    assert described["ChannelName"] == good_name


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")





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
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    _wait_stream_active(kinesis, name)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


def _channel_dest_and_role(ctx, account_id):
    """Provisions a *real*, assumable IAM service execution role (with a Kinesis-Data-Streams
    delivery trust policy and an S3 delivery permission policy) plus a real destination bucket,
    since CreateChannel validates that it can actually assume ServiceExecutionRoleARN before it
    validates anything else about the request."""
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]
    role_arn = role["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name))

    s3 = ctx.client("s3")
    if region == "us-east-1":
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
    """A freshly-created IAM role is not always immediately assumable (eventual consistency),
    so retry a CreateChannel that is expected to succeed while it still reports the transient
    "Unable to assume the service execution role" ValidationException. Real AWS validates
    ChannelName syntax deterministically on every attempt (an invalid name always reports the
    pattern-constraint message, never the role message), so
    any other ValidationException reason is permanent and must not be retried."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return kinesis.create_channel(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "")
            transient = code == "LimitExceededException" or (
                code == "ValidationException" and "assume" in msg.lower()
            )
            if transient and time.monotonic() < deadline:
                time.sleep(3)
                continue

            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

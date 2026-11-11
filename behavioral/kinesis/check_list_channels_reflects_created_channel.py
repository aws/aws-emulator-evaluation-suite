"""list-channels-reflects-created-channel."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-channels-reflects-created-channel"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A newly created channel appears in ListChannels (scoped by StreamFilter) and
    disappears after DeleteChannel."""
    kinesis = ctx.client("kinesis")

    bucket_arn = _create_bucket(ctx)
    role_arn = _create_channel_role(ctx, bucket_arn)
    _, stream_arn = _create_ondemand_stream(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    channel_name = ctx.unique_name("sim2real-kinch-")
    resp = _create_channel_with_retry(
        ctx,
        ChannelName=channel_name,
        ServiceExecutionRoleARN=role_arn,
        StreamConfigurationList=[
            {"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "STRING"}}
        ],
        S3DestinationConfiguration={
            "StorageConfiguration": {
                "BucketARN": bucket_arn,
                "ExpectedBucketOwner": account_id,
                "CompressionType": "NONE",
            }
        },
    )
    channel_arn = resp["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: _delete_channel_ignore_missing(ctx, channel_arn))
    _wait_channel_status(ctx, channel_arn, {"ACTIVE", "FAILED"}, timeout_s=180)

    names = _list_channel_names(ctx, stream_arn)
    assert channel_name in names, f"expected {channel_name} in ListChannels output, got {names}"

    kinesis.delete_channel(ChannelARN=channel_arn)

    deadline = time.monotonic() + 120
    names = _list_channel_names(ctx, stream_arn)
    while channel_name in names and time.monotonic() < deadline:
        time.sleep(3)
        names = _list_channel_names(ctx, stream_arn)
    assert channel_name not in names, f"expected {channel_name} removed from ListChannels, got {names}"

    try:
        kinesis.describe_channel(ChannelARN=channel_arn)
        raise AssertionError(
            f"expected DescribeChannel on deleted {channel_arn} to fail, got a successful response"
        )
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException for deleted channel {channel_arn}, got {code}"
        )
        message = e.response["Error"].get("Message")
        # AWS names the channel by its id, the last segment of the ARN.
        expected_message = f"Channel {channel_arn.rsplit('/', 1)[-1]} under account {ctx.account} not found."
        assert message == expected_message, (
            f"expected message {expected_message!r}, got {message!r}"
        )


def _list_channel_names(ctx, stream_arn: str) -> list[str]:
    kinesis = ctx.client("kinesis")
    names: list[str] = []
    kwargs = {"StreamFilter": [{"StreamARN": stream_arn}]}
    while True:
        resp = kinesis.list_channels(**kwargs)
        names.extend(s["ChannelName"] for s in resp.get("ChannelSummaries", []))
        token = resp.get("NextToken")
        if not token:
            return names
        kwargs = {"StreamFilter": [{"StreamARN": stream_arn}], "NextToken": token}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-kinch-b-").lower()
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, name))
    return f"arn:aws:s3:::{name}"


def _empty_and_delete_bucket(ctx, name) -> None:
    s3 = ctx.client("s3")
    try:
        resp = s3.list_objects_v2(Bucket=name)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


def _create_channel_role(ctx, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-kinch-role-")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    trust_policy = {
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
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    ctx.on_cleanup(lambda: _delete_role_ignore_missing(ctx, role_name))

    policy_name = "sim2real-kinch-policy"
    policy_doc = {
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
                "Resource": f"{bucket_arn}/*",
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: _delete_role_policy_ignore_missing(ctx, role_name, policy_name))
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _delete_role_ignore_missing(ctx, role_name: str) -> None:
    try:
        ctx.client("iam").delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_role_policy_ignore_missing(ctx, role_name: str, policy_name: str) -> None:
    try:
        ctx.client("iam").delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_ondemand_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kinch-strm-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(ctx, name))
    _wait_stream_status(ctx, name, {"ACTIVE"}, timeout_s=180)
    arn = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamARN"]
    return name, arn


def _delete_stream_ignore_missing(ctx, name: str) -> None:
    try:
        ctx.client("kinesis").delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _wait_stream_status(ctx, name: str, target_statuses, timeout_s: float = 180.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]["StreamStatus"]
        if status in target_statuses:
            return status
        time.sleep(3)
    raise AssertionError(f"stream {name} did not reach {target_statuses} in {timeout_s}s (last={status})")


def _wait_channel_status(ctx, channel_arn: str, target_statuses, timeout_s: float = 180.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]["ChannelStatus"]
        if status in target_statuses:
            return status
        time.sleep(3)
    raise AssertionError(f"channel {channel_arn} did not reach {target_statuses} in {timeout_s}s (last={status})")


def _delete_channel_ignore_missing(ctx, channel_arn: str) -> None:
    try:
        ctx.client("kinesis").delete_channel(ChannelARN=channel_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_channel_with_retry(ctx, **kwargs):
    """CreateChannel can transiently fail with AccessDenied/InvalidArgument right after the
    IAM role is created, before IAM's eventual-consistency window closes. Retry for ~90s."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + 150
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return kinesis.create_channel(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidArgumentException") or (
                code == "ValidationException" and "assume the service execution role" in str(e)
            ):
                last_exc = e
                time.sleep(5)
                continue
            raise
    assert last_exc is not None, "create_channel retry loop exited without recording an error"
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

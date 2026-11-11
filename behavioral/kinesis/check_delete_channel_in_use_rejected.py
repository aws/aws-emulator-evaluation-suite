"""delete-channel-in-use-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-channel-in-use-rejected"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteChannel on an already-deleted channel is rejected with ResourceNotFound.

    A sibling channel's single delete is the positive control that a first delete succeeds."""
    kinesis = ctx.client("kinesis")

    bucket_arn = _create_bucket(ctx)
    role_arn = _create_channel_role(ctx, bucket_arn)
    # Kinesis allows at most one S3-destination channel per stream, so each channel under
    # test needs its own source stream.
    _, stream_arn_target = _create_ondemand_stream(ctx)
    _, stream_arn_control = _create_ondemand_stream(ctx)
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    channel_arn_target = _create_channel(ctx, role_arn, stream_arn_target, bucket_arn, account_id)
    channel_arn_control = _create_channel(ctx, role_arn, stream_arn_control, bucket_arn, account_id)

    kinesis.delete_channel(ChannelARN=channel_arn_target)

    final_code, final_message = _wait_channel_gone(kinesis, channel_arn_target)
    assert final_code == "ResourceNotFoundException", f"expected channel removed, got code={final_code}"
    expected = f"Channel {channel_arn_target.rsplit('/', 1)[1]} under account {ctx.account} not found."
    assert final_message == expected, f"expected message {expected!r}, got {final_message!r}"

    second_code, second_message = _refusal(lambda: kinesis.delete_channel(ChannelARN=channel_arn_target))
    assert second_code == "ResourceNotFoundException", (
        f"expected re-deleting an already-deleted channel to be rejected with "
        f"ResourceNotFoundException, got {second_code}"
    )
    expected = f"Channel {channel_arn_target.rsplit('/', 1)[1]} under account {ctx.account} not found."
    assert second_message == expected, f"expected message {expected!r}, got {second_message!r}"

    kinesis.delete_channel(ChannelARN=channel_arn_control)
    describe_code, describe_message = _wait_channel_gone(kinesis, channel_arn_control)
    assert describe_code == "ResourceNotFoundException", (
        f"positive control delete did not take effect, got {describe_code}"
    )
    expected = f"Channel {channel_arn_control.rsplit('/', 1)[1]} under account {ctx.account} not found."
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"



def _refusal(fn):
    """Error code and message of a call that MUST be refused. A success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _wait_channel_gone(kinesis, channel_arn: str, timeout_s: float = 120.0):
    """Poll DescribeChannel until it reports ResourceNotFoundException; return (code, message)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"].get("ChannelStatus")
        except ClientError as exc:
            err = exc.response["Error"]
            last = (err["Code"], err.get("Message"))
            if err["Code"] == "ResourceNotFoundException":
                return last
        time.sleep(3)
    raise AssertionError(f"channel {channel_arn} still describable after {timeout_s}s (last={last!r})")


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
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
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


def _create_channel(ctx, role_arn: str, stream_arn: str, bucket_arn: str, account_id: str) -> str:
    ctx.client("kinesis")
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
    return channel_arn


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
    assert last_exc is not None, "create_channel retry loop exited with no captured exception"
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

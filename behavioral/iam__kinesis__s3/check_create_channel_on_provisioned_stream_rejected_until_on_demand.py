"""create-channel-on-provisioned-stream-rejected-until-on-demand."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-on-provisioned-stream-rejected-until-on-demand"
GROUP = "validation"
SERVICES = ["iam", "kinesis", "s3"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel on a PROVISIONED source stream is refused with ValidationException and no
    channel is created; the identical call succeeds once the stream switches to ON_DEMAND."""
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-kinchprov-")
    kinesis.create_stream(
        StreamName=stream_name, ShardCount=1, StreamModeDetails={"StreamMode": "PROVISIONED"}
    )
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(ctx, stream_name))
    summary = _wait_stream_status(ctx, stream_name, {"ACTIVE"}, timeout_s=180)
    stream_arn = summary["StreamARN"]
    assert summary["StreamModeDetails"]["StreamMode"] == "PROVISIONED", (
        f"expected the stream to come up PROVISIONED, got {summary['StreamModeDetails']}"
    )

    bucket = _create_channel_bucket(ctx)
    role_arn = _create_channel_role(ctx, stream_arn, bucket["arn"])
    channel_name = ctx.unique_name("sim2real-kinchprov-chan-")

    def _attempt_create():
        return kinesis.create_channel(
            ChannelName=channel_name,
            ServiceExecutionRoleARN=role_arn,
            StreamConfigurationList=[
                {"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}
            ],
            S3DestinationConfiguration={
                "StorageConfiguration": {
                    "BucketARN": bucket["arn"],
                    "CompressionType": "NONE",
                    "ExpectedBucketOwner": ctx.account,
                },
                "DataFreshnessInSeconds": 300,
            },
        )

    code, message = _refusal_tolerating_iam_propagation(_attempt_create)
    assert code == "ValidationException", (
        f"expected CreateChannel against a PROVISIONED stream to fail with ValidationException, "
        f"got {code}: {message}"
    )
    expected_message = (
        f"Request is invalid. Stream {stream_name} under account {ctx.account} is in "
        "Provisioned mode. Please enable On-demand mode to use this feature."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    assert not _channel_names(kinesis, channel_name), (
        f"CreateChannel was refused but a channel named {channel_name!r} is visible in ListChannels"
    )

    kinesis.update_stream_mode(StreamARN=stream_arn, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    _wait_stream_mode(ctx, stream_name, "ON_DEMAND", timeout_s=180)

    resp = _create_channel_with_retry(_attempt_create)
    channel_arn = resp["ChannelDescription"]["ChannelARN"]

    def _cleanup():
        try:
            kinesis.delete_channel(ChannelARN=channel_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    desc = _wait_for_channel_status(ctx, channel_arn, {"ACTIVE", "FAILED"})
    assert desc["ChannelStatus"] == "ACTIVE", (
        f"CreateChannel against the same stream after switching to ON_DEMAND did not reach "
        f"ACTIVE: {desc.get('ChannelStatusReason')}"
    )
    assert desc["StreamConfigurationList"][0]["StreamARN"] == stream_arn, (
        f"expected the active channel's source StreamARN={stream_arn!r}, "
        f"got {desc['StreamConfigurationList'][0]['StreamARN']!r}"
    )


def _channel_names(kinesis, wanted_name) -> list:
    names = []
    kwargs: dict[str, Any] = {"MaxResults": 100}
    while True:
        page = kinesis.list_channels(**kwargs)
        names.extend(c["ChannelName"] for c in page.get("ChannelSummaries", []) if c["ChannelName"] == wanted_name)
        next_token = page.get("NextToken")
        if not next_token:
            return names
        kwargs = {"MaxResults": 100, "NextToken": next_token}


def _refusal_tolerating_iam_propagation(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """(code, message) of a call expected to end in a terminal refusal, tolerating the
    transient AccessDenied/InvalidArgument window while the IAM role is still propagating."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response["Error"]
            code, message = err["Code"], err.get("Message", "")
            if code == "AccessDeniedException" or (
                code == "ValidationException" and "assume the service execution role" in message
            ):
                if time.monotonic() >= deadline:
                    raise AssertionError(f"IAM propagation never settled within {timeout_s}s: {message}")
                time.sleep(interval_s)
                continue
            return code, message
        raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _create_channel_with_retry(fn, timeout_s: float = 90.0, interval_s: float = 5.0):
    """CreateChannel can transiently fail with AccessDenied/InvalidArgument right after the IAM
    role is created, before IAM's eventual-consistency window closes."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidArgumentException") or (
                code == "ValidationException" and "assume the service execution role" in str(e)
            ):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    assert last_exc is not None, "retry loop exited without ever calling CreateChannel"
    raise last_exc


def _delete_stream_ignore_missing(ctx, name: str) -> None:
    try:
        ctx.client("kinesis").delete_stream(StreamName=name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _wait_stream_status(ctx, name: str, target_statuses, timeout_s: float = 180.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] in target_statuses:
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {name} did not reach {target_statuses} in {timeout_s}s (last={summary})")


def _wait_stream_mode(ctx, name: str, target_mode: str, timeout_s: float = 180.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE" and summary["StreamModeDetails"]["StreamMode"] == target_mode:
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {name} did not settle at mode {target_mode} in {timeout_s}s (last={summary})")


def _wait_for_channel_status(ctx, channel_arn, targets, timeout_s=240.0, interval_s=5.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
        if last["ChannelStatus"] in targets:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"channel {channel_arn} did not reach {targets} in {timeout_s}s (last={last!r})")


def _create_channel_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-kinchprov-bkt-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        try:
            resp = s3.list_objects_v2(Bucket=name)
            for obj in resp.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _create_channel_role(ctx, stream_arn, bucket_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-kinchprov-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "kinesis.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-kinchprov-policy"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "kinesis:DescribeStreamSummary",
                    "kinesis:DescribeStreamConsumer",
                    "kinesis:RegisterStreamConsumer",
                    "kinesis:DeregisterStreamConsumer",
                    "kinesis:SubscribeToShard",
                    "kinesis:GetShardIterator",
                    "kinesis:GetRecords",
                    "kinesis:ListShards",
                ],
                "Resource": [stream_arn, f"{stream_arn}/*"],
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:ListBucket",
                    "s3:AbortMultipartUpload",
                    "s3:GetBucketLocation",
                ],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            },
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

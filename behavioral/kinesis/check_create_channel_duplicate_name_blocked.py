"""create-channel-duplicate-name-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-channel-duplicate-name-blocked"
GROUP = "negative-classes"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateChannel reusing a still-CREATING ChannelName is rejected with
    ResourceInUseException, not accepted or overwritten; an unused name succeeds normally."""
    kinesis = ctx.client("kinesis")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket_arn = _create_scratch_bucket(ctx)
    role_arn = _create_channel_role(ctx, bucket_arn)
    stream_arn = _create_ondemand_stream(ctx)
    other_stream_arn = _create_ondemand_stream(ctx)

    channel_name = ctx.unique_name("sim2real-behav-chandup-")
    channel_kwargs = dict(
        ChannelName=channel_name,
        ServiceExecutionRoleARN=role_arn,
        S3DestinationConfiguration={
            "StorageConfiguration": {
                "BucketARN": bucket_arn,
                "CompressionType": "NONE",
                "ExpectedBucketOwner": account_id,
            }
        },
        StreamConfigurationList=[
            {
                "StreamARN": stream_arn,
                "RecordConfiguration": {"RecordFormatType": "JSON"},
            }
        ],
    )
    first = _create_channel_with_retry(kinesis, channel_kwargs)
    first_arn = first["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: _safe_delete_channel(kinesis, first_arn))

    # The duplicate attempt binds a DIFFERENT stream than the original. If it
    # reused the identical config, an implementation that silently accepted
    # the duplicate (a no-op "success") would be indistinguishable from one
    # that correctly rejected it -- every field read back would match either
    # way. Binding a different stream makes an accepted duplicate observable
    # below via the independent read.
    duplicate_kwargs = dict(channel_kwargs)
    duplicate_kwargs["StreamConfigurationList"] = [
        {"StreamARN": other_stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}
    ]
    # The service execution role can still be propagating to the host that serves this
    # second call even though the first create already assumed it; that refusal names the
    # role, not the name collision, so it is retried within a bounded window.
    deadline = time.monotonic() + 60
    duplicate = None
    while True:
        try:
            duplicate = kinesis.create_channel(**duplicate_kwargs)
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            message = response.get("Error", {}).get("Message") if response else None
            if (
                code == "ValidationException"
                and "assume the service execution role" in (message or "")
                and time.monotonic() < deadline
            ):
                time.sleep(5)
                continue
            break
        else:
            break
    if duplicate is not None:
        # An unexpected SUCCESS fails here with what happened, not as a later
        # code mismatch; the created channel still gets a cleanup.
        leaked_arn = duplicate["ChannelDescription"]["ChannelARN"]
        ctx.on_cleanup(lambda: _safe_delete_channel(kinesis, leaked_arn))
        raise AssertionError(
            f"expected ResourceInUseException for a duplicate ChannelName, but the "
            f"duplicate create SUCCEEDED and returned {leaked_arn!r}"
        )
    assert code == "ResourceInUseException", (
        f"expected ResourceInUseException for a duplicate ChannelName, got {code!r}: {message!r}"
    )
    expected = f"Channel {channel_name} under account {ctx.account} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the original channel is untouched -- same name, same
    # ARN, and still bound to its own stream rather than rebound to the
    # rejected duplicate's stream -- and there is exactly one channel with
    # this name (the duplicate attempt created nothing)
    described = kinesis.describe_channel(ChannelARN=first_arn)["ChannelDescription"]
    assert described["ChannelName"] == channel_name, (
        f"expected ChannelName {channel_name!r}, got {described['ChannelName']!r}"
    )
    assert described["ChannelARN"] == first_arn, (
        f"expected ChannelARN {first_arn!r}, got {described['ChannelARN']!r}"
    )
    described_streams = {c["StreamARN"] for c in described["StreamConfigurationList"]}
    assert described_streams == {stream_arn}, (
        f"rejected duplicate must not rebind the channel's stream: "
        f"expected {{{stream_arn!r}}}, got {described_streams!r}"
    )

    # positive control: a channel with a different name, attached to the
    # other stream (each stream permits only one S3-destination channel), is
    # created without issue -- proving the account/role/API are otherwise
    # healthy and this isn't "every CreateChannel fails"
    other_name = ctx.unique_name("sim2real-behav-chanok-")
    other_kwargs = dict(channel_kwargs)
    other_kwargs["ChannelName"] = other_name
    other_kwargs["StreamConfigurationList"] = [
        {"StreamARN": other_stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}
    ]
    second = _create_channel_with_retry(kinesis, other_kwargs)
    second_arn = second["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: _safe_delete_channel(kinesis, second_arn))
    assert second_arn != first_arn, "the positive control must be a distinct channel"

    # terminal read: independent of the mutating CreateChannel call above
    described_2 = kinesis.describe_channel(ChannelARN=second_arn)["ChannelDescription"]
    assert described_2["ChannelName"] == other_name, (
        f"expected ChannelName {other_name!r}, got {described_2['ChannelName']!r}"
    )
    assert described_2["ChannelARN"] == second_arn, (
        f"expected ChannelARN {second_arn!r}, got {described_2['ChannelARN']!r}"
    )


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-channel-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {}
    # us-east-1 is the one region where CreateBucket rejects an explicit
    # LocationConstraint; every other region requires it.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket_name, **kwargs)

    def _cleanup() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return f"arn:aws:s3:::{bucket_name}"


def _create_channel_role(ctx, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    role_name = ctx.unique_name("sim2real-behav-chanrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "kinesis.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnLike": {
                        "aws:SourceArn": f"arn:aws:kinesis:{ctx.region}:{account_id}:channel/*"
                    },
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe_delete_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="s3-delivery",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "s3:ListBucket", "s3:GetBucketLocation"],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    }
                ],
            }
        ),
    )
    return role_arn


def _safe_delete_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="s3-delivery")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_ondemand_stream(ctx) -> str:
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-behav-chanstream-")
    kinesis.create_stream(
        StreamName=stream_name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: _safe_delete_stream(kinesis, stream_name))
    summary = _wait_stream_active(kinesis, stream_name)
    return summary["StreamARN"]


def _wait_stream_active(kinesis, stream_name: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    summary = None
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)["StreamDescriptionSummary"]
        if summary["StreamStatus"] == "ACTIVE":
            return summary
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} never became ACTIVE, last={summary}")


def _create_channel_with_retry(kinesis, kwargs: dict[str, Any], timeout_s: float = 150.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return kinesis.create_channel(**kwargs)
        except Exception as exc:  # noqa: BLE001
            # IAM role trust/permission propagation can lag briefly after creation
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            message = response.get("Error", {}).get("Message", "") if response else ""
            if code == "AccessDeniedException" or (
                code == "ValidationException" and "assume the service execution role" in message
            ):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"create_channel kept failing on IAM propagation: {last_exc}")


def _safe_delete_channel(kinesis, channel_arn: str) -> None:
    """Delete the channel; retry only ResourceInUseException (still CREATING) for up to 60 s."""
    deadline = time.monotonic() + 60
    while True:
        try:
            kinesis.delete_channel(ChannelARN=channel_arn)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_stream(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

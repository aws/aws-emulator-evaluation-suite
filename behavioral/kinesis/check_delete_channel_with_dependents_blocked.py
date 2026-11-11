"""delete-channel-with-dependents-blocked."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-channel-with-dependents-blocked"
GROUP = "overly-permissive"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteStream on a stream with an attached channel fails with ResourceInUseException.

    The stream survives the rejection and the same delete succeeds once the channel is gone;
    a stream with no channel is the positive control that deletes outright."""
    kinesis = ctx.client("kinesis")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # positive control: a stream with no dependents deletes outright
    control_name = ctx.unique_name("sim2real-behav-chanplainstrm-")
    _create_ondemand_stream(ctx, control_name)
    kinesis.delete_stream(StreamName=control_name, EnforceConsumerDeletion=True)
    _wait_stream_gone(kinesis, control_name)

    # break: attach a channel to a fresh stream
    bucket_arn = _create_scratch_bucket(ctx)
    role_arn = _create_channel_role(ctx, bucket_arn)
    target_name = ctx.unique_name("sim2real-behav-chandepstrm-")
    target_stream_arn = _create_ondemand_stream(ctx, target_name)

    channel_kwargs = dict(
        ChannelName=ctx.unique_name("sim2real-behav-chandbldel-"),
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
                "StreamARN": target_stream_arn,
                "RecordConfiguration": {"RecordFormatType": "JSON"},
            }
        ],
    )
    channel = _create_channel_with_retry(kinesis, channel_kwargs)
    channel_arn = channel["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: _safe_delete_channel(kinesis, channel_arn))

    # assert the specific error: DeleteStream is rejected while the channel is attached
    code, message = _error(
        lambda: kinesis.delete_stream(StreamName=target_name, EnforceConsumerDeletion=True)
    )
    assert code == "ResourceInUseException", (
        f"expected DeleteStream on a stream with an attached channel to fail with "
        f"ResourceInUseException, got {code!r}"
    )
    expected_message = (
        f"Stream {target_name} under account {account_id} cannot be deleted because it is "
        "associated with one or more channels. Delete all associated channels before deleting "
        "the stream."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # assert the effect is absent via an independent read: the stream survives
    status = kinesis.describe_stream_summary(StreamName=target_name)["StreamDescriptionSummary"][
        "StreamStatus"
    ]
    assert status == "ACTIVE", f"stream should still be ACTIVE after the rejected delete, got {status!r}"

    # restore: remove the dependent channel
    kinesis.delete_channel(ChannelARN=channel_arn)
    _wait_channel_gone(kinesis, channel_arn)

    # the SAME delete call now succeeds
    kinesis.delete_stream(StreamName=target_name, EnforceConsumerDeletion=True)
    _wait_stream_gone(kinesis, target_name)


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-behav-chandep-").lower().replace("_", "-")
    kwargs: dict[str, Any] = {}
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
    role_name = ctx.unique_name("sim2real-behav-chandeprole-")
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


def _create_ondemand_stream(ctx, stream_name: str) -> str:
    kinesis = ctx.client("kinesis")
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


def _wait_stream_gone(kinesis, stream_name: str, timeout_s: float = 180.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_stream_summary(StreamName=stream_name)
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            if response is not None and response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} was never fully deleted")


def _create_channel_with_retry(kinesis, kwargs: dict[str, Any], timeout_s: float = 150.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return kinesis.create_channel(**kwargs)
        except Exception as exc:  # noqa: BLE001
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


def _wait_channel_gone(kinesis, channel_arn: str, timeout_s: float = 60.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_channel(ChannelARN=channel_arn)
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            if code == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"channel {channel_arn} was never fully deleted")


def _safe_delete_stream(kinesis, stream_name: str) -> None:
    try:
        kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn) -> tuple[str | None, str | None]:
    """Call fn(); return the (code, message) of the service error it raises. A success raises."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is None:
            raise
        err = response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""update-channel-properties-persist."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-channel-properties-persist"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannel mutations (DataFreshnessInSeconds) are durably reflected in a
    subsequent DescribeChannel call, after the channel returns from UPDATING to ACTIVE."""
    channel = _create_active_channel(ctx, data_freshness=300)
    kinesis = ctx.client("kinesis")

    before = kinesis.describe_channel(ChannelARN=channel["arn"])["ChannelDescription"]
    assert before["S3DestinationConfiguration"]["DataFreshnessInSeconds"] == 300

    # DataFreshnessInSeconds must be between 300 and 900 (real AWS rejects values outside that
    # range with a ValidationException), so update to another in-range value.
    kinesis.update_channel(
        ChannelARN=channel["arn"],
        S3DestinationConfiguration={"DataFreshnessInSeconds": 600},
    )

    desc = _wait_for_channel_status(ctx, channel["arn"], {"ACTIVE", "FAILED"})
    if desc["ChannelStatus"] != "ACTIVE":
        raise AssertionError(f"channel did not return to ACTIVE after update: {desc.get('ChannelStatusReason')}")

    after = kinesis.describe_channel(ChannelARN=channel["arn"])["ChannelDescription"]
    assert after["S3DestinationConfiguration"]["DataFreshnessInSeconds"] == 600, (
        f"expected updated DataFreshnessInSeconds=600, got {after['S3DestinationConfiguration']}"
    )
    # Immutable fields must remain untouched by the update.
    assert after["ServiceExecutionRoleARN"] == channel["role_arn"]
    assert after["StreamConfigurationList"][0]["StreamARN"] == channel["stream"]["arn"]


def _error_code(fn):
    try:
        fn()
        return None
    except ClientError as e:
        return e.response["Error"]["Code"]


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _account_id(ctx):
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_ondemand_stream(ctx):
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-kch-")
    kinesis.create_stream(StreamName=name, StreamModeDetails={"StreamMode": "ON_DEMAND"})

    def _cleanup():
        try:
            kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    summary = _poll_until(
        lambda: kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"],
        lambda s: s["StreamStatus"] == "ACTIVE",
        timeout_s=120,
        interval_s=3,
    )
    return {"name": name, "arn": summary["StreamARN"]}


def _create_channel_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-kchbkt-").lower().replace("_", "-")
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
    return {"name": name, "arn": f"arn:aws:s3:::{name}"}


def _create_channel_role(ctx, stream_arn, bucket_arn):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-kchrole-")
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-behav-kch-policy"
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


def _create_channel_with_retry(ctx, **kwargs):
    """CreateChannel can transiently reject while IAM's eventual-consistency window for the
    just-created role/policy is still open. Real AWS reports this as ValidationException
    ("Unable to assume the service execution role"), not AccessDenied.
    Retry on that specific signal with a deadline; anything else raises immediately."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + 90.0
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return kinesis.create_channel(**kwargs)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code in ("AccessDeniedException", "InvalidArgumentException") or (
                code == "ValidationException" and "assume the service execution role" in message
            ):
                last_exc = e
                time.sleep(5)
                continue
            raise
    assert last_exc is not None
    raise last_exc


def _wait_for_channel_status(ctx, channel_arn, targets, timeout_s=240.0, interval_s=5.0):
    kinesis = ctx.client("kinesis")

    def _probe():
        return kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]

    return _poll_until(_probe, lambda d: d["ChannelStatus"] in targets, timeout_s=timeout_s, interval_s=interval_s)


def _create_active_channel(ctx, data_freshness=None):
    stream = _create_ondemand_stream(ctx)
    bucket = _create_channel_bucket(ctx)
    role_arn = _create_channel_role(ctx, stream["arn"], bucket["arn"])
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-behav-channel-")

    s3_dest: dict[str, Any] = {
        "StorageConfiguration": {
            "BucketARN": bucket["arn"],
            "CompressionType": "NONE",
            "ExpectedBucketOwner": _account_id(ctx),
        }
    }
    if data_freshness is not None:
        s3_dest["DataFreshnessInSeconds"] = data_freshness

    resp = _create_channel_with_retry(
        ctx,
        ChannelName=name,
        ServiceExecutionRoleARN=role_arn,
        StreamConfigurationList=[
            {"StreamARN": stream["arn"], "RecordConfiguration": {"RecordFormatType": "JSON"}}
        ],
        S3DestinationConfiguration=s3_dest,
    )
    channel_arn = resp["ChannelDescription"]["ChannelARN"]

    def _cleanup():
        try:
            kinesis.delete_channel(ChannelARN=channel_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    desc = _wait_for_channel_status(ctx, channel_arn, {"ACTIVE", "FAILED"})
    if desc["ChannelStatus"] != "ACTIVE":
        raise AssertionError(f"channel did not reach ACTIVE: {desc.get('ChannelStatusReason')}")
    return {
        "arn": channel_arn,
        "name": name,
        "stream": stream,
        "bucket": bucket,
        "role_arn": role_arn,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""create-channel-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-lifecycle"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """CreateChannel transitions the channel to ACTIVE and it is visible in
    ListChannels/DescribeChannel until DeleteChannel removes it, after which the ARN is
    dead: an independent read 404s and a further mutation on it fails the same way."""
    channel = _create_active_channel(ctx)
    kinesis = ctx.client("kinesis")

    desc = kinesis.describe_channel(ChannelARN=channel["arn"])["ChannelDescription"]
    assert desc["ChannelStatus"] == "ACTIVE", (
        f"expected ChannelStatus=ACTIVE, got {desc['ChannelStatus']!r}"
    )
    assert desc["ChannelName"] == channel["name"], (
        f"expected ChannelName={channel['name']!r}, got {desc['ChannelName']!r}"
    )
    assert desc["ServiceExecutionRoleARN"] == channel["role_arn"], (
        f"expected ServiceExecutionRoleARN={channel['role_arn']!r}, "
        f"got {desc['ServiceExecutionRoleARN']!r}"
    )
    assert desc["StreamConfigurationList"][0]["StreamARN"] == channel["stream"]["arn"], (
        f"expected source StreamARN={channel['stream']['arn']!r}, "
        f"got {desc['StreamConfigurationList'][0]['StreamARN']!r}"
    )

    found = False
    next_token = None
    for _ in range(50):
        kwargs: dict[str, Any] = {"MaxResults": 100}
        if next_token:
            kwargs["NextToken"] = next_token
        page = kinesis.list_channels(**kwargs)
        if any(c["ChannelARN"] == channel["arn"] for c in page.get("ChannelSummaries", [])):
            found = True
            break
        next_token = page.get("NextToken")
        if not next_token:
            break
    assert found, "active channel was not visible in ListChannels"

    kinesis.delete_channel(ChannelARN=channel["arn"])
    _wait_for_channel_deleted(ctx, channel["arn"])

    # The dead ARN is not just unreadable -- a further mutation against it must fail the same
    # way, not with a different error class that would suggest the channel is half-alive.
    redelete_code, redelete_message = _refusal(lambda: kinesis.delete_channel(ChannelARN=channel["arn"]))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected DeleteChannel on a deleted channel to report ResourceNotFoundException, "
        f"got {redelete_code}"
    )
    expected = f"Channel {channel["arn"].rsplit('/', 1)[1]} under account {ctx.account} not found."
    assert redelete_message == expected, f"expected message {expected!r}, got {redelete_message!r}"


def _refusal(fn):
    """Error code and message of a call that MUST be refused. A success is a failure."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


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
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": CHECK},
    )

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
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]
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


def _create_channel_with_retry(kinesis, timeout_s=90.0, interval_s=5.0, **kwargs):
    """CreateChannel can transiently fail with AccessDenied/InvalidArgument right after the
    IAM role is created, before IAM's eventual-consistency window closes. Bounded retry
    instead of a fixed sleep, since the propagation delay varies."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return kinesis.create_channel(**kwargs)
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


def _wait_for_channel_status(ctx, channel_arn, targets, timeout_s=240.0, interval_s=5.0):
    kinesis = ctx.client("kinesis")

    def _probe():
        return kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]

    return _poll_until(_probe, lambda d: d["ChannelStatus"] in targets, timeout_s=timeout_s, interval_s=interval_s)


def _wait_for_channel_deleted(ctx, channel_arn, timeout_s=180.0, interval_s=5.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            kinesis.describe_channel(ChannelARN=channel_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"channel {channel_arn} was not removed within {timeout_s}s")


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
        kinesis,
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

    # TagResource rejects a channel still in CREATING with ResourceInUseException, so tag
    # only once the channel has left that state.
    desc = _wait_for_channel_status(ctx, channel_arn, {"ACTIVE", "FAILED"})
    kinesis.tag_resource(ResourceARN=channel_arn, Tags={"sim2real": CHECK})
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

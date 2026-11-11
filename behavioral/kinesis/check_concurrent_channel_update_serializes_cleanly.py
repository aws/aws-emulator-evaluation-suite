"""concurrent-channel-update-serializes-cleanly."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-channel-update-serializes-cleanly"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateChannel calls on one ACTIVE channel: at least one succeeds, any failure is
    ResourceInUseException with the exact "not ACTIVE, instead in state UPDATING." message, and the channel
    settles ACTIVE with DataFreshnessInSeconds equal to one of the submitted values."""
    channel = _create_active_channel(ctx)
    kinesis = ctx.client("kinesis")

    def _attempt(freshness: int):
        try:
            kinesis.update_channel(
                ChannelARN=channel["arn"],
                S3DestinationConfiguration={"DataFreshnessInSeconds": freshness},
            )
            return ("ok", None, None)
        except ClientError as e:
            return ("error", e.response["Error"]["Code"], e.response["Error"]["Message"])

    # DataFreshnessInSeconds must be 300-900; two distinct valid values mean any rejection comes
    # from the state-machine conflict, not input validation.
    submitted = (300, 600)
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_attempt, f) for f in submitted]
        results = [f.result() for f in futures]

    errors = [r[1:] for r in results if r[0] == "error"]
    oks = [r for r in results if r[0] == "ok"]
    want_message = (
        f"Channel {channel['name']} under account {ctx.account} not ACTIVE, instead in state UPDATING."
    )
    for code, message in errors:
        assert code == "ResourceInUseException", (
            f"a racer failed with an unexpected code (only ResourceInUseException, for a "
            f"channel already UPDATING/CREATING/DELETING, is an acceptable rejection), "
            f"got code={code!r}, results={results}"
        )
        assert message == want_message, f"expected message {want_message!r}, results={results}"
    assert len(oks) >= 1, f"expected at least one racer to succeed, got {results}"

    desc = _wait_for_channel_status(ctx, channel["arn"], {"ACTIVE", "FAILED"})
    assert desc["ChannelStatus"] == "ACTIVE", f"channel left in {desc['ChannelStatus']} after racing updates"

    final_freshness = desc["S3DestinationConfiguration"]["DataFreshnessInSeconds"]
    assert final_freshness in submitted, (
        f"expected settled DataFreshnessInSeconds to be one of the racers' submitted values "
        f"{submitted}, got {final_freshness} (results={results})"
    )


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
        Tags={"sim2real": "ga-depth-kinesis"},
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


def _create_channel_with_retry(kinesis, kwargs: dict[str, Any], timeout_s: float = 150.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return kinesis.create_channel(**kwargs)
        except ClientError as exc:
            # IAM role trust/permission propagation can lag briefly after creation.
            code = exc.response.get("Error", {}).get("Code")
            message = exc.response.get("Error", {}).get("Message", "")
            if code == "AccessDeniedException" or (
                code == "ValidationException" and "assume the service execution role" in message
            ):
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"create_channel kept failing on IAM propagation: {last_exc}")


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
        kinesis,
        dict(
            ChannelName=name,
            ServiceExecutionRoleARN=role_arn,
            StreamConfigurationList=[
                {"StreamARN": stream["arn"], "RecordConfiguration": {"RecordFormatType": "JSON"}}
            ],
            S3DestinationConfiguration=s3_dest,
        ),
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

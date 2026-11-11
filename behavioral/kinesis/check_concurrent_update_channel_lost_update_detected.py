"""concurrent-update-channel-lost-update-detected."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-update-channel-lost-update-detected"
GROUP = "concurrency"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateChannel calls with divergent LoggingConfiguration: at least one succeeds, any
    failure is ResourceInUseException with the exact not-ACTIVE message, and the channel settles ACTIVE with
    exactly one of the two configurations in full (never a partial merge of the LogStreamName values)."""
    channel_arn, log_group_name = _setup_channel(ctx)
    kinesis = ctx.client("kinesis")

    # Warm up: IAM role/CloudWatch Logs permissions can take a few seconds to
    # propagate to the point where Kinesis can actually validate log-group access.
    # Do this serially, before the race, so the race itself measures concurrency
    # semantics rather than permission-propagation flakiness.
    _wait_logging_config_usable(ctx, channel_arn, log_group_name)

    def _update(tag):
        try:
            kinesis.update_channel(
                ChannelARN=channel_arn,
                LoggingConfiguration={
                    "CloudWatchLogs": {
                        "Enabled": True,
                        "LogGroupName": log_group_name,
                        "LogStreamName": f"sim2real-{tag}",
                    }
                },
            )
            return ("ok", tag, None)
        except Exception as exc:  # noqa: BLE001
            return ("err", tag, _error_code(exc), _error_message(exc))


    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_update, ["a", "b"]))

    successes = [r for r in results if r[0] == "ok"]
    assert len(successes) >= 1, f"expected at least one UpdateChannel to succeed, got {results}"
    for r in results:
        if r[0] == "err":
            assert r[2] == "ResourceInUseException", r

    final = _wait_channel_status(ctx, channel_arn, {"ACTIVE", "FAILED"})
    assert final["ChannelStatus"] == "ACTIVE", (
        f"expected ACTIVE after the race, got {final['ChannelStatus']}: {final.get('ChannelStatusReason')}"
    )
    want_message = (
        f"Channel {final['ChannelName']} under account {ctx.account} not ACTIVE, instead in state UPDATING."
    )
    for r in results:
        if r[0] == "err":
            assert r[3] == want_message, f"expected message {want_message!r}, got {r}"
    log_stream = final["LoggingConfiguration"]["CloudWatchLogs"]["LogStreamName"]
    assert log_stream in ("sim2real-a", "sim2real-b"), (
        f"expected the settled LogStreamName to be exactly one racer's value "
        f"('sim2real-a' or 'sim2real-b'), got {log_stream!r} -- a value outside that set "
        f"would mean the two concurrent updates merged into something neither racer submitted"
    )
    assert final["LoggingConfiguration"]["CloudWatchLogs"]["Enabled"] is True, (
        f"expected CloudWatchLogs.Enabled True to persist through the race, got "
        f"{final['LoggingConfiguration']['CloudWatchLogs']['Enabled']!r}"
    )


def _error_code(exc):
    resp = getattr(exc, "response", None)
    if resp is None:
        return None
    return resp.get("Error", {}).get("Code")


def _error_message(exc):
    resp = getattr(exc, "response", None)
    if resp is None:
        return str(exc)
    return resp.get("Error", {}).get("Message")


def _wait_logging_config_usable(ctx, channel_arn, log_group_name, timeout_s=90.0):
    """Serially retries an UpdateChannel call with a warm-up logging config until it
    succeeds (or a non-transient error occurs), so IAM/CloudWatch Logs permission
    propagation delay doesn't leak into the concurrency assertion below."""
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            kinesis.update_channel(
                ChannelARN=channel_arn,
                LoggingConfiguration={
                    "CloudWatchLogs": {
                        "Enabled": True,
                        "LogGroupName": log_group_name,
                        "LogStreamName": "sim2real-warmup",
                    }
                },
            )
            _wait_channel_status(ctx, channel_arn, {"ACTIVE", "FAILED"})
            return
        except Exception as exc:  # noqa: BLE001
            last = f"{_error_code(exc)}: {_error_message(exc)}"
            time.sleep(3)
    raise AssertionError(f"UpdateChannel warm-up never succeeded within {timeout_s}s, last={last}")


def _setup_channel(ctx):
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    logs = ctx.client("logs")
    sts = ctx.client("sts")
    account = sts.get_caller_identity()["Account"]

    stream_name = ctx.unique_name("sim2real-behav-chsrc-")
    kinesis.create_stream(
        StreamName=stream_name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "behavioral"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True))
    stream_arn = _wait_stream_active(ctx, stream_name)

    bucket = ctx.unique_name("sim2real-behav-chdest-").lower().replace("_", "-")
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "behavioral"}]})
    bucket_arn = f"arn:aws:s3:::{bucket}"

    log_group_name = ctx.unique_name("/sim2real-behav/chlogs-")
    logs.create_log_group(logGroupName=log_group_name, tags={"sim2real": "behavioral"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group_name))
    log_group_arn = f"arn:aws:logs:{ctx.region}:{account}:log-group:{log_group_name}:*"

    role_name = ctx.unique_name("sim2real-behav-chrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "kinesis.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account},
                    "ArnLike": {"aws:SourceArn": f"arn:aws:kinesis:{ctx.region}:{account}:channel/*"},
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    inline_policy = {
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
                "Resource": [f"{bucket_arn}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups", "logs:DescribeLogStreams"],
                "Resource": [log_group_arn, f"arn:aws:logs:{ctx.region}:{account}:log-group:{log_group_name}"],
            },
        ],
    }
    policy_name = "sim2real-behav-inline-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    channel_name = ctx.unique_name("sim2real-behav-channel-")
    channel_arn, code = _create_channel_polling(
        ctx, channel_name, role_arn, stream_arn, account, bucket_arn, None
    )
    assert channel_arn is not None, f"CreateChannel never succeeded: {code}"
    ctx.on_cleanup(lambda: ctx.client("kinesis").delete_channel(ChannelARN=channel_arn))

    _wait_channel_status(ctx, channel_arn, {"ACTIVE", "FAILED"})
    return channel_arn, log_group_name


def _create_channel_polling(ctx, channel_name, role_arn, stream_arn, account, bucket_arn, key_id, timeout_s=90.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    last_code = None
    last_message = None
    while True:
        kwargs = dict(
            ChannelName=channel_name,
            ServiceExecutionRoleARN=role_arn,
            StreamConfigurationList=[
                {"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}
            ],
            S3DestinationConfiguration={
                "DataFreshnessInSeconds": 300,
                "StorageConfiguration": {
                    "BucketARN": bucket_arn,
                    "ExpectedBucketOwner": account,
                    "CompressionType": "NONE",
                },
            },
        )
        if key_id is not None:
            kwargs["EncryptionConfiguration"] = {"EncryptionType": "KMS", "KeyId": key_id}
        kwargs["Tags"] = {"sim2real": "behavioral"}
        try:
            resp = kinesis.create_channel(**kwargs)
            return resp["ChannelDescription"]["ChannelARN"], None
        except Exception as exc:  # noqa: BLE001
            last_code = _error_code(exc)
            last_message = _error_message(exc)
            transient = last_code == "AccessDeniedException" or (
                last_code == "ValidationException"
                and last_message
                and "assume" in last_message.lower()
            )
            if transient and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return None, f"{last_code}: {last_message}"


def _wait_stream_active(ctx, name, timeout_s=120.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"]
        if desc["StreamStatus"] == "ACTIVE":
            return desc["StreamARN"]
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE")


def _wait_channel_status(ctx, channel_arn, terminal_statuses, timeout_s=120.0):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    desc = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
        if desc["ChannelStatus"] in terminal_statuses:
            return desc
        time.sleep(3)
    raise AssertionError(f"channel {channel_arn} never reached {terminal_statuses}, last={desc}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

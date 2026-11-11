"""s3-channel-echoes-freshness-and-refuses-below-minimum-while-put-records-accepted."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-channel-echoes-freshness-and-refuses-below-minimum-while-put-records-accepted"
GROUP = "data-plane"
SERVICES = ["iam", "kinesis", "s3"]

_N = 15
_DATA_FRESHNESS_S = 300
#: Documented data freshness range of an S3 delivery, in seconds.
_FRESHNESS_MIN_S, _FRESHNESS_MAX_S = 300, 900
_FRESHNESS_OUT_OF_RANGE = (
    "ValidationException",
    f"DataFreshnessInSeconds must be between {_FRESHNESS_MIN_S} and {_FRESHNESS_MAX_S}.",
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel refuses an S3 delivery fresher than the documented 300 s minimum and creates
    no channel; at 300 s the channel goes ACTIVE, DescribeChannel echoes the freshness, storage and
    the default dead-letter bucket, and the stream accepts every PutRecords entry.

    Reference: https://docs.aws.amazon.com/streams/latest/dev/data-delivery-s3-about.html
    """
    kinesis = ctx.client("kinesis")
    stream_name = ctx.unique_name("sim2real-kinchs3-")
    kinesis.create_stream(StreamName=stream_name, StreamModeDetails={"StreamMode": "ON_DEMAND"})
    ctx.on_cleanup(lambda: _delete_stream_ignore_missing(ctx, stream_name))
    summary = _wait_stream_status(ctx, stream_name, {"ACTIVE"}, timeout_s=180)
    stream_arn = summary["StreamARN"]

    bucket = _create_channel_bucket(ctx)
    role_arn = _create_channel_role(ctx, stream_arn, bucket["arn"])

    def _request(name: str, freshness: int) -> dict:
        return {
            "ChannelName": name,
            "ServiceExecutionRoleARN": role_arn,
            "StreamConfigurationList": [
                {"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}
            ],
            "S3DestinationConfiguration": {
                "StorageConfiguration": {
                    "BucketARN": bucket["arn"],
                    "CompressionType": "NONE",
                    "ExpectedBucketOwner": ctx.account,
                },
                "DataFreshnessInSeconds": freshness,
            },
        }

    bad_name = ctx.unique_name("sim2real-kinchs3-bad-")
    got = _create_channel_error(ctx, kinesis, **_request(bad_name, _FRESHNESS_MIN_S - 1))
    assert got == _FRESHNESS_OUT_OF_RANGE, (
        f"DataFreshnessInSeconds={_FRESHNESS_MIN_S - 1} is below the documented minimum; expected "
        f"{_FRESHNESS_OUT_OF_RANGE!r}, got {got!r}"
    )
    assert bad_name not in _channel_names(kinesis, stream_arn), (
        f"CreateChannel was refused but a channel named {bad_name!r} is visible in ListChannels"
    )

    channel_name = ctx.unique_name("sim2real-kinchs3-chan-")
    resp = _create_channel_with_retry(kinesis, **_request(channel_name, _DATA_FRESHNESS_S))
    channel_arn = resp["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: _delete_channel_and_wait_gone(kinesis, channel_arn))
    desc = _wait_for_channel_status(ctx, channel_arn, {"ACTIVE", "FAILED"})
    assert desc["ChannelStatus"] == "ACTIVE", (
        f"channel did not reach ACTIVE: {desc.get('ChannelStatusReason')}"
    )
    dest = desc["S3DestinationConfiguration"]
    assert dest["DataFreshnessInSeconds"] == _DATA_FRESHNESS_S, (
        f"DescribeChannel echoes DataFreshnessInSeconds {dest['DataFreshnessInSeconds']!r}, "
        f"expected {_DATA_FRESHNESS_S}"
    )
    storage = {k: dest["StorageConfiguration"].get(k) for k in ("BucketARN", "CompressionType", "ExpectedBucketOwner")}
    assert storage == {"BucketARN": bucket["arn"], "CompressionType": "NONE", "ExpectedBucketOwner": ctx.account}, (
        f"DescribeChannel echoes the storage configuration as {storage!r}"
    )
    # With no dead-letter queue configured, the delivery defaults to the destination bucket.
    dlq_bucket = dest["DeadLetterQueueS3Configuration"].get("BucketARN")
    assert dlq_bucket == bucket["arn"], (
        f"the default dead-letter queue bucket reads {dlq_bucket!r}, expected the destination "
        f"bucket {bucket['arn']!r}"
    )
    streams = [(c["StreamARN"], c["RecordConfiguration"]["RecordFormatType"]) for c in desc["StreamConfigurationList"]]
    assert streams == [(stream_arn, "JSON")], f"DescribeChannel echoes the streams as {streams!r}"
    assert _channel_names(kinesis, stream_arn) == {channel_name}, (
        f"ListChannels for the stream must list only {channel_name!r}"
    )

    token = ctx.unique_name("sim2real-kinchs3-tok-")
    partition_keys = [ctx.unique_name(f"sim2real-kinchs3-pk{i}-") for i in range(5)]
    entries = [
        {"Data": json.dumps({"token": token, "seq": i}).encode(), "PartitionKey": partition_keys[i % 5]}
        for i in range(_N)
    ]
    put_resp = kinesis.put_records(StreamName=stream_name, Records=entries)
    assert put_resp["FailedRecordCount"] == 0, (
        f"PutRecords reported {put_resp['FailedRecordCount']} failed entries: {put_resp['Records']!r}"
    )
    results = put_resp["Records"]
    seq_numbers = {r.get("SequenceNumber") for r in results} - {None}
    assert len(results) == _N and len(seq_numbers) == _N, (
        f"expected {_N} entries with distinct SequenceNumbers, got {results!r}"
    )
    # Records sharing a partition key hash to one shard.
    shards_by_key: dict[str, set] = {}
    for entry, result in zip(entries, results):
        shards_by_key.setdefault(entry["PartitionKey"], set()).add(result.get("ShardId"))
    split = {k: v for k, v in shards_by_key.items() if len(v) != 1 or None in v}
    assert not split, f"entries sharing a partition key landed on more than one shard: {split!r}"


def _channel_names(kinesis, stream_arn) -> set:
    names = set()
    for page in kinesis.get_paginator("list_channels").paginate(StreamFilter=[{"StreamARN": stream_arn}]):
        names.update(s["ChannelName"] for s in page["ChannelSummaries"])
    return names


def _create_channel_error(ctx, kinesis, timeout_s=90.0, interval_s=5.0, **kwargs):
    """(code, message) of a CreateChannel refusal, past the IAM propagation refusals of a new role."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            resp = kinesis.create_channel(**kwargs)
        except ClientError as e:
            err = e.response["Error"]
            propagating = err["Code"] in ("AccessDeniedException", "InvalidArgumentException") or (
                err["Code"] == "ValidationException" and "assume the service execution role" in err.get("Message", "")
            )
            if propagating and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return err["Code"], err.get("Message")
        arn = resp["ChannelDescription"]["ChannelARN"]
        ctx.on_cleanup(lambda: _delete_channel_and_wait_gone(kinesis, arn))
        raise AssertionError(f"CreateChannel accepted {kwargs['ChannelName']!r}: {resp['ChannelDescription']!r}")


_TRANSITIONAL_CHANNEL_STATUSES = ("CREATING", "UPDATING")


def _channel_status(kinesis, channel_arn: str) -> str | None:
    """The channel's ChannelStatus, or None once DescribeChannel reports it not found."""
    try:
        return kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]["ChannelStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _delete_channel_and_wait_gone(kinesis, channel_arn: str, timeout_s: float = 180.0) -> None:
    """DeleteChannel, then wait until DescribeChannel reports it gone.

    A refused delete is retried only while the channel reads CREATING or UPDATING; a channel
    already DELETING skips straight to the wait."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            kinesis.delete_channel(ChannelARN=channel_arn)
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code not in ("ResourceInUseException", "InvalidArgumentException"):
                raise
            status = _channel_status(kinesis, channel_arn)
            if status is None:
                return
            if status == "DELETING":
                break
            if status not in _TRANSITIONAL_CHANNEL_STATUSES or time.monotonic() > deadline:
                raise
            time.sleep(5)
    while time.monotonic() < deadline:
        if _channel_status(kinesis, channel_arn) is None:
            return
        time.sleep(5)
    raise AssertionError(f"channel {channel_arn} still describable {timeout_s}s after delete")


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


def _create_channel_with_retry(kinesis, timeout_s=90.0, interval_s=5.0, **kwargs):
    """CreateChannel can transiently fail with AccessDenied/InvalidArgument right after the
    IAM role is created, before IAM's eventual-consistency window closes."""
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


def _create_channel_bucket(ctx):
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-kinchs3-bkt-").lower().replace("_", "-")
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
    role_name = ctx.unique_name("sim2real-kinchs3-role-")
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

    policy_name = "sim2real-kinchs3-policy"
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

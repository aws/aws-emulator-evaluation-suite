"""s3-channel-delivers-every-put-records-payload-once."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-channel-delivers-every-put-records-payload-once"
GROUP = "data-plane"
SERVICES = ["iam", "kinesis", "s3"]

_N = 15
_DATA_FRESHNESS_S = 300
_DELIVERY_BUDGET_S = 900.0


# timing:real-time — buffer: 300 s
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An S3 channel on an ACTIVE on-demand stream delivers every PutRecords payload to the
    destination bucket, none missing and none repeated among the objects read once all appear.

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
    channel_name = ctx.unique_name("sim2real-kinchs3-chan-")

    resp = _create_channel_with_retry(
        kinesis,
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
            "DataFreshnessInSeconds": _DATA_FRESHNESS_S,
        },
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
    assert desc["ChannelStatus"] == "ACTIVE", (
        f"channel did not reach ACTIVE: {desc.get('ChannelStatusReason')}"
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

    seqs = _poll_until_delivered(ctx, bucket["name"], token, _N, timeout_s=_DELIVERY_BUDGET_S)
    assert len(seqs) == _N, (
        f"expected exactly {_N} delivered payloads within {_DELIVERY_BUDGET_S}s, "
        f"found {len(seqs)}: sequence numbers {sorted(seqs)}"
    )
    assert seqs == list(range(_N)), (
        f"expected sequence numbers 0..{_N - 1} with none missing and none duplicated, "
        f"got {sorted(seqs)}"
    )


def _poll_until_delivered(ctx, bucket_name: str, token: str, want: int, timeout_s: float):
    """Every ``seq`` value seen across all delivered objects carrying ``token``, until ``want``
    distinct values are found or the deadline passes."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    seen: list = []
    while True:
        seen = []
        kwargs: dict[str, Any] = {"Bucket": bucket_name}
        while True:
            page = s3.list_objects_v2(**kwargs)
            for obj in page.get("Contents", []):
                body = s3.get_object(Bucket=bucket_name, Key=obj["Key"])["Body"].read()
                for record in _decode_json_records(body.decode("utf-8")):
                    if isinstance(record, dict) and record.get("token") == token:
                        seen.append(record["seq"])
            token_page = page.get("NextContinuationToken")
            if not token_page:
                break
            kwargs = {"Bucket": bucket_name, "ContinuationToken": token_page}
        if len(set(seen)) >= want or time.monotonic() >= deadline:
            return sorted(seen)
        time.sleep(2)


def _decode_json_records(text: str) -> list:
    """Every JSON value in ``text``, back to back with or without a delimiter between them."""
    decoder = json.JSONDecoder()
    idx = 0
    out = []
    length = len(text)
    while idx < length:
        while idx < length and text[idx] in " \t\r\n":
            idx += 1
        if idx >= length:
            break
        obj, end = decoder.raw_decode(text, idx)
        out.append(obj)
        idx = end
    return out


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

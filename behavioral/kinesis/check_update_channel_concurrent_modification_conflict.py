"""update-channel-concurrent-modification-conflict."""
from __future__ import annotations

import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-channel-concurrent-modification-conflict"
GROUP = "concurrency"
SERVICES = ["kinesis"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Of two concurrent UpdateChannel calls on one channel, exactly one fails with
    ResourceInUseException and the exact not-ACTIVE message, and the channel returns to ACTIVE
    with the winner's DataFreshnessInSeconds."""
    kinesis = ctx.client("kinesis")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")

    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    bucket_name = ctx.unique_name("sim2real-kinesis-ch-")
    _create_bucket(ctx, s3, bucket_name, region)
    bucket_arn = f"arn:aws:s3:::{bucket_name}"

    role_name = ctx.unique_name("sim2real-kinesis-ch-role-")
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
                        "aws:SourceArn": f"arn:aws:kinesis:{region}:{account_id}:channel/*"
                    },
                },
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    permission_policy = {
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
        ],
    }
    policy_name = "sim2real-kinesis-ch-s3-policy"
    iam.put_role_policy(
        RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(permission_policy)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    stream_name = ctx.unique_name("sim2real-behav-")
    kinesis.create_stream(
        StreamName=stream_name, StreamModeDetails={"StreamMode": "ON_DEMAND"}
    )
    ctx.on_cleanup(
        lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
    )
    _wait_stream_active(kinesis, stream_name)
    stream_arn = kinesis.describe_stream_summary(StreamName=stream_name)[
        "StreamDescriptionSummary"
    ]["StreamARN"]

    channel_name = ctx.unique_name("sim2real-channel-")
    channel_arn = _create_channel_with_role_propagation_retry(
        kinesis,
        channel_name=channel_name,
        role_arn=role_arn,
        stream_arn=stream_arn,
        bucket_arn=bucket_arn,
        account_id=account_id,
    )
    ctx.on_cleanup(lambda: _cleanup_delete_channel(kinesis, channel_arn))
    _wait_channel_status(kinesis, channel_arn, "ACTIVE", timeout_s=180.0)

    value_a, value_b = 400, 700
    barrier = threading.Barrier(2)

    def racer(freshness: int):
        barrier.wait(timeout=10)
        return kinesis.update_channel(
            ChannelARN=channel_arn,
            S3DestinationConfiguration={"DataFreshnessInSeconds": freshness},
        )

    from botocore.exceptions import ClientError

    outcomes = []
    conflict_message = None
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = {
            pool.submit(racer, value_a): value_a,
            pool.submit(racer, value_b): value_b,
        }
        for future, freshness in futures.items():
            try:
                future.result(timeout=30)
                outcomes.append(("ok", freshness))
            except ClientError as e:
                outcomes.append((e.response["Error"]["Code"], freshness))
                conflict_message = e.response["Error"]["Message"]

    successes = [freshness for status, freshness in outcomes if status == "ok"]
    conflicts = [status for status, _ in outcomes if status != "ok"]
    assert len(successes) == 1, f"expected exactly one winner, got outcomes={outcomes}"
    assert conflicts == ["ResourceInUseException"], f"expected one conflict, got {outcomes}"
    assert conflict_message == (
        f"Channel {channel_name} under account {account_id} not ACTIVE, instead in state UPDATING."
    ), f"unexpected conflict message: {conflict_message!r}"

    winner_freshness = successes[0]
    final = _wait_channel_status(kinesis, channel_arn, "ACTIVE", timeout_s=180.0)
    assert (
        final["S3DestinationConfiguration"]["DataFreshnessInSeconds"] == winner_freshness
    ), "final channel config does not reflect the winning racer's value"


def _create_bucket(ctx, s3, bucket_name: str, region: str) -> None:
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region}
        )

    def _delete_bucket():
        objects = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objects:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)

    ctx.on_cleanup(_delete_bucket)


def _wait_stream_active(kinesis, name: str, timeout_s: float = 120.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = kinesis.describe_stream_summary(StreamName=name)["StreamDescriptionSummary"][
            "StreamStatus"
        ]
        if status == "ACTIVE":
            return
        time.sleep(2)
    raise AssertionError(f"stream {name} never became ACTIVE within {timeout_s}s")


def _create_channel_with_role_propagation_retry(
    kinesis, *, channel_name, role_arn, stream_arn, bucket_arn, account_id, timeout_s: float = 90.0
):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            resp = kinesis.create_channel(
                ChannelName=channel_name,
                ServiceExecutionRoleARN=role_arn,
                StreamConfigurationList=[
                    {"StreamARN": stream_arn, "RecordConfiguration": {"RecordFormatType": "JSON"}}
                ],
                S3DestinationConfiguration={
                    "DataFreshnessInSeconds": 300,
                    "StorageConfiguration": {
                        "BucketARN": bucket_arn,
                        "CompressionType": "NONE",
                        "ExpectedBucketOwner": account_id,
                    },
                },
            )
            return resp["ChannelDescription"]["ChannelARN"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            transient = code in ("AccessDeniedException", "InvalidArgumentException") or (
                code == "ValidationException"
                and ("assume" in message.lower() or "s3 bucket" in message.lower())
            )
            if transient:
                last_error = e
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"CreateChannel never succeeded (IAM propagation?): {last_error}")


def _wait_channel_status(kinesis, channel_arn: str, expected: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        desc = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
        last = desc
        if desc["ChannelStatus"] == expected:
            return desc
        time.sleep(3)
    raise AssertionError(f"channel never reached {expected}, last description={last}")


def _cleanup_delete_channel(kinesis, channel_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        kinesis.delete_channel(ChannelARN=channel_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise
        return
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            kinesis.describe_channel(ChannelARN=channel_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(2)
    raise AssertionError(f"channel {channel_arn} still exists 90 s after DeleteChannel")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

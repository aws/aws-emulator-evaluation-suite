"""create-channel-then-describe-shows-active."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-then-describe-shows-active"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel followed by DescribeChannel returns the channel ACTIVE with matching config."""
    infra = _create_channel_infra(ctx)
    channel_name = ctx.unique_name("sim2real-kch-act-")
    desc = _create_channel(ctx, infra, channel_name)
    channel_arn = desc["ChannelARN"]

    final = _wait_channel_status(ctx, channel_arn)
    assert final["ChannelStatus"] == "ACTIVE", (
        f"channel did not reach ACTIVE, status={final['ChannelStatus']} "
        f"reason={final.get('ChannelStatusReason')}"
    )
    assert final["ChannelName"] == channel_name, (
        f"expected ChannelName={channel_name!r}, got {final['ChannelName']!r}"
    )
    assert final["ServiceExecutionRoleARN"] == infra["role_arn"], (
        f"expected ServiceExecutionRoleARN={infra['role_arn']!r}, "
        f"got {final['ServiceExecutionRoleARN']!r}"
    )
    assert final["StreamConfigurationList"][0]["StreamARN"] == infra["stream_arn"], (
        f"expected source StreamARN={infra['stream_arn']!r}, "
        f"got {final['StreamConfigurationList'][0]['StreamARN']!r}"
    )
    got_bucket_arn = final["S3DestinationConfiguration"]["StorageConfiguration"]["BucketARN"]
    assert got_bucket_arn == infra["bucket_arn"], (
        f"expected destination BucketARN={infra['bucket_arn']!r}, got {got_bucket_arn!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_delivery_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-kch-bkt-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(
            Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )

    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "ga-depth-kinesis"}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            )
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name, f"arn:aws:s3:::{name}"


def _wait_stream_active(ctx, stream_name: str, timeout_s: float = 120.0) -> str:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        summary = kinesis.describe_stream_summary(StreamName=stream_name)[
            "StreamDescriptionSummary"
        ]
        if summary["StreamStatus"] == "ACTIVE":
            return summary["StreamARN"]
        time.sleep(3)
    raise AssertionError(f"stream {stream_name} did not become ACTIVE within {timeout_s}s")


def _create_source_stream(ctx) -> tuple[str, str]:
    kinesis = ctx.client("kinesis")
    name = ctx.unique_name("sim2real-kch-strm-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "ga-depth-kinesis"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    arn = _wait_stream_active(ctx, name)
    return name, arn


def _create_delivery_role(ctx, bucket_arn: str, account_id: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-kch-role-")
    trust = json.dumps(
        {
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
    )
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": "ga-depth-kinesis"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_name = "delivery-policy"
    perms = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DeliveryBucketList",
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket", "s3:ListBucketMultipartUploads"],
                    "Resource": [bucket_arn, f"{bucket_arn}/*"],
                },
                {
                    "Sid": "DeliveryBucketWrite",
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
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=perms)

    def _cleanup() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_channel_infra(ctx) -> dict:
    account_id = _account_id(ctx)
    bucket_name, bucket_arn = _create_delivery_bucket(ctx)
    stream_name, stream_arn = _create_source_stream(ctx)
    role_arn = _create_delivery_role(ctx, bucket_arn, account_id)
    return {
        "account_id": account_id,
        "bucket_name": bucket_name,
        "bucket_arn": bucket_arn,
        "stream_name": stream_name,
        "stream_arn": stream_arn,
        "role_arn": role_arn,
    }


def _create_channel(ctx, infra: dict, channel_name: str, data_freshness: int | None = None) -> dict:
    kinesis = ctx.client("kinesis")
    storage = {
        "BucketARN": infra["bucket_arn"],
        "ExpectedBucketOwner": infra["account_id"],
        "CompressionType": "NONE",
    }
    s3_dest: dict = {"StorageConfiguration": storage}
    if data_freshness is not None:
        s3_dest["DataFreshnessInSeconds"] = data_freshness

    last_err: Exception | None = None
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            resp = kinesis.create_channel(
                ChannelName=channel_name,
                ServiceExecutionRoleARN=infra["role_arn"],
                StreamConfigurationList=[
                    {
                        "StreamARN": infra["stream_arn"],
                        "RecordConfiguration": {"RecordFormatType": "JSON"},
                    }
                ],
                S3DestinationConfiguration=s3_dest,
                Tags={"sim2real": "ga-depth-kinesis"},
            )
            channel_arn = resp["ChannelDescription"]["ChannelARN"]
            ctx.on_cleanup(lambda arn=channel_arn: _delete_channel_and_wait_gone(ctx, arn))
            return resp["ChannelDescription"]
        except ClientError as exc:
            last_err = exc
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            role_not_yet_assumable = code == "ValidationException" and "assume" in message.lower()
            if code in ("AccessDeniedException", "InvalidArgumentException") or role_not_yet_assumable:
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"CreateChannel never succeeded (last error: {last_err})")


def _delete_channel_and_wait_gone(ctx, channel_arn: str, timeout_s: float = 180.0) -> None:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    deleted = False
    while time.monotonic() < deadline:
        try:
            kinesis.delete_channel(ChannelARN=channel_arn)
            deleted = True
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceInUseException":
                time.sleep(5)
                continue
            if code in ("InvalidArgumentException", "ResourceNotFoundException"):
                return
            raise
    if not deleted:
        raise AssertionError(f"DeleteChannel on {channel_arn} kept conflicting for {timeout_s}s")
    while time.monotonic() < deadline:
        try:
            kinesis.describe_channel(ChannelARN=channel_arn)
        except ClientError:
            return
        time.sleep(5)
    raise AssertionError(f"channel {channel_arn} still describable {timeout_s}s after delete")


def _wait_channel_status(ctx, channel_arn: str, timeout_s: float = 240.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
        if desc["ChannelStatus"] in ("ACTIVE", "FAILED"):
            return desc
        time.sleep(5)
    raise AssertionError(f"channel {channel_arn} did not settle within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

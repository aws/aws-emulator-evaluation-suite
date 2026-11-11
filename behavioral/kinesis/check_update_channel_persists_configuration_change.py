"""update-channel-persists-configuration-change."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-channel-persists-configuration-change"
GROUP = "state-machine"
SERVICES = ["kinesis"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannel's modified configuration is durably reflected on a later DescribeChannel."""
    infra = _create_channel_infra(ctx)
    channel_name = ctx.unique_name("sim2real-kch-upd-")
    desc = _create_channel(ctx, infra, channel_name)
    channel_arn = desc["ChannelARN"]

    active = _wait_channel_status(ctx, channel_arn)
    assert active["ChannelStatus"] == "ACTIVE", (
        f"channel never reached ACTIVE, status={active['ChannelStatus']} "
        f"reason={active.get('ChannelStatusReason')}"
    )
    original_freshness = active["S3DestinationConfiguration"].get("DataFreshnessInSeconds", 300)
    new_freshness = 900 if original_freshness != 900 else 600

    kinesis = ctx.client("kinesis")
    kinesis.update_channel(
        ChannelARN=channel_arn,
        S3DestinationConfiguration={"DataFreshnessInSeconds": new_freshness},
    )

    updated = _wait_channel_status(ctx, channel_arn)
    assert updated["ChannelStatus"] == "ACTIVE", (
        f"channel left ACTIVE after UpdateChannel, status={updated['ChannelStatus']} "
        f"reason={updated.get('ChannelStatusReason')}"
    )
    assert updated["S3DestinationConfiguration"]["DataFreshnessInSeconds"] == new_freshness, (
        f"expected DataFreshnessInSeconds={new_freshness}, "
        f"got {updated['S3DestinationConfiguration']}"
    )

    # Durability: an independent, later DescribeChannel call still reflects the change.
    redescribed = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
    assert redescribed["S3DestinationConfiguration"]["DataFreshnessInSeconds"] == new_freshness, (
        f"expected durable DataFreshnessInSeconds={new_freshness} on independent re-describe, "
        f"got {redescribed['S3DestinationConfiguration']}"
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
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
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
        Tags={"sim2real": CHECK},
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
        Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _create_channel(ctx, infra: dict, channel_name: str) -> dict:
    kinesis = ctx.client("kinesis")
    s3_dest = {
        "StorageConfiguration": {
            "BucketARN": infra["bucket_arn"],
            "ExpectedBucketOwner": infra["account_id"],
            "CompressionType": "NONE",
        }
    }
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
                Tags={"sim2real": CHECK},
            )
            channel_arn = resp["ChannelDescription"]["ChannelARN"]
            ctx.on_cleanup(lambda arn=channel_arn: _delete_channel_and_wait_gone(ctx, arn))
            return resp["ChannelDescription"]
        except ClientError as exc:
            last_err = exc
            code = exc.response["Error"]["Code"]
            if code in ("AccessDeniedException", "InvalidArgumentException") or (
                code == "ValidationException"
                and "assume the service execution role" in str(exc)
            ):
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

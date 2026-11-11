"""create-channel-output-key-template-variants-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-channel-output-key-template-variants-rejected"
GROUP = "negative-classes"
SERVICES = ["iam", "kinesis", "s3"]

_ROLE_PROPAGATION_DEADLINE_S = 120.0

_TRAVERSAL = (
    "ValidationException",
    "OutputKeyTemplate must not contain consecutive periods, period-only path segments, or start with /",
)
_SLASHES = ("ValidationException", "OutputKeyTemplate must not contain consecutive slashes (//)")
_UNCLOSED = ("ValidationException", "OutputKeyTemplate contains an unclosed variable placeholder")
_BAD_VARIABLE = (
    "ValidationException",
    "OutputKeyTemplate contains invalid variable: !{partition-id}",
)

_VARIANTS = (
    ("a/../b", _TRAVERSAL),
    ("a//b", _SLASHES),
    ("/a", _TRAVERSAL),
    ("!{foo", _UNCLOSED),
    ("!{partition-id}", _BAD_VARIABLE),
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Every invalid S3 OutputKeyTemplate is rejected; a valid one is accepted and reads back.

    Reference: https://docs.aws.amazon.com/kinesis/data-delivery-s3-key-template.html
    """
    infra = _create_channel_infra(ctx)

    for index, (template, (code, message)) in enumerate(_VARIANTS):
        channel_name = ctx.unique_name(f"sim2real-xsvc-oktv-bad{index}-")
        got_code, got_message = _create_channel_expect_error(ctx, infra, channel_name, template)
        assert got_code == code, f"template {template!r}: expected code {code!r}, got {got_code!r}"
        assert got_message == message, (
            f"template {template!r}: expected message {message!r}, got {got_message!r}"
        )

    after_rejections = _list_channel_names(ctx, infra["stream_arn"])
    assert after_rejections == set(), f"a rejected template left a channel behind: {after_rejections!r}"

    valid_template = "sim2real/!{channel-name}/!{channel-id}/!{yyyy}/!{MM}/!{dd}/!{HH}!{extension}"
    valid_channel_name = ctx.unique_name("sim2real-xsvc-oktv-ok-")
    desc = _create_channel(ctx, infra, valid_channel_name, valid_template)
    final = _wait_channel_status(ctx, desc["ChannelARN"])
    assert final["ChannelStatus"] == "ACTIVE", (
        f"valid-template channel did not reach ACTIVE, status={final['ChannelStatus']!r} "
        f"reason={final.get('ChannelStatusReason')!r}"
    )
    got_template = final["S3DestinationConfiguration"]["StorageConfiguration"]["OutputKeyTemplate"]
    assert got_template == valid_template, (
        f"expected OutputKeyTemplate={valid_template!r}, got {got_template!r}"
    )

    final_names = _list_channel_names(ctx, infra["stream_arn"])
    assert final_names == {valid_channel_name}, (
        f"expected only {valid_channel_name!r} on this stream, got {final_names!r}"
    )


def _create_delivery_bucket(ctx) -> tuple[str, str]:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-xsvc-oktv-bkt-").lower()
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    s3.put_bucket_tagging(
        Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "xsvc-oktv"}]}
    )
    return name, f"arn:aws:s3:::{name}"


def _delete_bucket(s3, name: str) -> None:
    objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
    if objs:
        s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
    s3.delete_bucket(Bucket=name)


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
    name = ctx.unique_name("sim2real-xsvc-oktv-strm-")
    kinesis.create_stream(
        StreamName=name,
        StreamModeDetails={"StreamMode": "ON_DEMAND"},
        Tags={"sim2real": "xsvc-oktv"},
    )
    ctx.on_cleanup(lambda: kinesis.delete_stream(StreamName=name, EnforceConsumerDeletion=True))
    arn = _wait_stream_active(ctx, name)
    return name, arn


def _create_delivery_role(ctx, bucket_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-xsvc-oktv-role-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "kinesis.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": ctx.account},
                        "ArnLike": {
                            "aws:SourceArn": f"arn:aws:kinesis:{ctx.region}:{ctx.account}:channel/*"
                        },
                    },
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real", "Value": "xsvc-oktv"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "delivery-policy"
    perms = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DeliveryBucketList",
                    "Effect": "Allow",
                    "Action": ["s3:ListBucket"],
                    "Resource": [bucket_arn],
                },
                {
                    "Sid": "DeliveryBucketWrite",
                    "Effect": "Allow",
                    "Action": ["s3:PutObject"],
                    "Resource": [f"{bucket_arn}/*"],
                },
            ],
        }
    )
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=perms)
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role_arn


def _create_channel_infra(ctx) -> dict:
    bucket_name, bucket_arn = _create_delivery_bucket(ctx)
    stream_name, stream_arn = _create_source_stream(ctx)
    role_arn = _create_delivery_role(ctx, bucket_arn)
    return {
        "bucket_name": bucket_name,
        "bucket_arn": bucket_arn,
        "stream_name": stream_name,
        "stream_arn": stream_arn,
        "role_arn": role_arn,
    }


def _call_create_channel(ctx, infra: dict, channel_name: str, template: str):
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + _ROLE_PROPAGATION_DEADLINE_S
    while True:
        try:
            return kinesis.create_channel(
                ChannelName=channel_name,
                ServiceExecutionRoleARN=infra["role_arn"],
                StreamConfigurationList=[
                    {
                        "StreamARN": infra["stream_arn"],
                        "RecordConfiguration": {"RecordFormatType": "JSON"},
                    }
                ],
                S3DestinationConfiguration={
                    "StorageConfiguration": {
                        "BucketARN": infra["bucket_arn"],
                        "ExpectedBucketOwner": ctx.account,
                        "CompressionType": "NONE",
                        "OutputKeyTemplate": template,
                    }
                },
                Tags={"sim2real": "xsvc-oktv"},
            )
        except ClientError as exc:
            err = exc.response["Error"]
            role_not_yet_assumable = err["Code"] == "ValidationException" and "assume" in err.get(
                "Message", ""
            ).lower()
            if role_not_yet_assumable and time.monotonic() < deadline:
                time.sleep(5)
                continue
            raise


def _create_channel_expect_error(ctx, infra: dict, channel_name: str, template: str) -> tuple[str, str]:
    """Calls CreateChannel with ``template`` and returns ``(code, message)``; raises on success."""
    try:
        resp = _call_create_channel(ctx, infra, channel_name, template)
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    channel_arn = resp["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: _delete_channel_and_wait_gone(ctx, channel_arn))
    raise AssertionError(
        f"CreateChannel with OutputKeyTemplate={template!r} unexpectedly succeeded: {channel_arn!r}"
    )


def _create_channel(ctx, infra: dict, channel_name: str, template: str) -> dict:
    resp = _call_create_channel(ctx, infra, channel_name, template)
    channel_arn = resp["ChannelDescription"]["ChannelARN"]
    ctx.on_cleanup(lambda: _delete_channel_and_wait_gone(ctx, channel_arn))
    return resp["ChannelDescription"]


_TRANSITIONAL_CHANNEL_STATUSES = ("CREATING", "UPDATING")


def _delete_channel_and_wait_gone(ctx, channel_arn: str, timeout_s: float = 180.0) -> None:
    """DeleteChannel, then wait until DescribeChannel reports it gone.

    A refused delete is retried only while the channel reads CREATING or UPDATING; a channel
    already DELETING skips straight to the wait."""
    kinesis = ctx.client("kinesis")
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


def _channel_status(kinesis, channel_arn: str) -> str | None:
    """The channel's ChannelStatus, or None once DescribeChannel reports it not found."""
    try:
        return kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]["ChannelStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return None
        raise


def _wait_channel_status(ctx, channel_arn: str, timeout_s: float = 240.0) -> dict:
    kinesis = ctx.client("kinesis")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = kinesis.describe_channel(ChannelARN=channel_arn)["ChannelDescription"]
        if desc["ChannelStatus"] in ("ACTIVE", "FAILED"):
            return desc
        time.sleep(5)
    raise AssertionError(f"channel {channel_arn} did not settle within {timeout_s}s")


def _list_channel_names(ctx, stream_arn: str) -> set[str]:
    kinesis = ctx.client("kinesis")
    names: set[str] = set()
    paginator = kinesis.get_paginator("list_channels")
    for page in paginator.paginate(StreamFilter=[{"StreamARN": stream_arn}]):
        for summary in page["ChannelSummaries"]:
            names.add(summary["ChannelName"])
    return names


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

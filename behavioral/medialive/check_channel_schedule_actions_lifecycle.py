"""channel-schedule-actions-lifecycle."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-schedule-actions-lifecycle"
GROUP = "state"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchUpdateSchedule creates/deletes actions and DescribeSchedule reflects each change."""
    medialive = ctx.client("medialive")
    role_arn = _iam_role_for_medialive(ctx)
    bucket = _s3_bucket_for_medialive(ctx)
    input_a = _create_pull_input(ctx, ctx.unique_name("sim2real-medialive-input-a-"))
    input_b = _create_pull_input(ctx, ctx.unique_name("sim2real-medialive-input-b-"))
    channel = _create_minimal_channel(
        ctx, ctx.unique_name("sim2real-medialive-chan-"), input_a["Id"], input_b["Id"], role_arn, bucket
    )
    channel_id = channel["Id"]

    future_time = (datetime.now(timezone.utc) + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    action_name = "sim2real-switch-1"
    medialive.batch_update_schedule(
        ChannelId=channel_id,
        Creates={
            "ScheduleActions": [
                {
                    "ActionName": action_name,
                    "ScheduleActionSettings": {
                        "InputSwitchSettings": {"InputAttachmentNameReference": "input2"}
                    },
                    "ScheduleActionStartSettings": {"FixedModeScheduleActionStartSettings": {"Time": future_time}},
                }
            ]
        },
    )

    schedule = medialive.describe_schedule(ChannelId=channel_id)["ScheduleActions"]
    names_after_create = {a["ActionName"] for a in schedule}
    assert action_name in names_after_create, f"expected {action_name} in schedule, got {names_after_create}"

    medialive.batch_update_schedule(ChannelId=channel_id, Deletes={"ActionNames": [action_name]})
    schedule_after_delete = medialive.describe_schedule(ChannelId=channel_id)["ScheduleActions"]
    names_after_delete = {a["ActionName"] for a in schedule_after_delete}
    assert action_name not in names_after_delete, f"{action_name} still present in schedule after delete"


# ===== helpers =====
def _iam_role_for_medialive(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-medialive-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "medialive.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "channel-schedule-actions-lifecycle"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _teardown(lambda: iam.delete_role(RoleName=role_name)))
    ctx.on_cleanup(lambda: _teardown(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)))
    return role_arn


def _s3_bucket_for_medialive(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-medialive-").lower().replace("_", "-")[:63].strip("-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is CreateBucket's one region where passing CreateBucketConfiguration at all
    # (even with a matching LocationConstraint) is rejected — this is a transport quirk of
    # the API, not a region pin on the bucket itself.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup_bucket():
        while objs := s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            for o in objs:
                s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(lambda: _teardown(_cleanup_bucket))
    return bucket


def _create_pull_input(ctx, name):
    medialive = ctx.client("medialive")
    resp = medialive.create_input(
        Name=name,
        Type="URL_PULL",
        Sources=[{"Url": "https://d3rlna7iyyu8wu.cloudfront.net/hls/bipbop_16x9.m3u8"}],
        Tags={"sim2real": "channel-schedule-actions-lifecycle"},
    )["Input"]
    ctx.on_cleanup(lambda: _teardown(lambda: _input_gone_step(medialive, resp["Id"])))
    return resp


def _minimal_encoder_settings():
    return {
        "AudioDescriptions": [
            {
                "Name": "audio_1",
                "AudioSelectorName": "default",
                "CodecSettings": {
                    "AacSettings": {"Bitrate": 192000.0, "CodingMode": "CODING_MODE_2_0", "SampleRate": 48000.0}
                },
            }
        ],
        "VideoDescriptions": [
            {
                "Name": "video_1",
                "Width": 640,
                "Height": 360,
                "CodecSettings": {
                    "H264Settings": {
                        "Bitrate": 1000000,
                        "RateControlMode": "CBR",
                        "FramerateControl": "SPECIFIED",
                        "FramerateNumerator": 30,
                        "FramerateDenominator": 1,
                        "GopSize": 90,
                        "GopSizeUnits": "FRAMES",
                        "ParControl": "SPECIFIED",
                        "ParNumerator": 1,
                        "ParDenominator": 1,
                    }
                },
            }
        ],
        "OutputGroups": [
            {
                "Name": "group1",
                "OutputGroupSettings": {"ArchiveGroupSettings": {"Destination": {"DestinationRefId": "destination1"}}},
                "Outputs": [
                    {
                        "OutputName": "output1",
                        "VideoDescriptionName": "video_1",
                        "AudioDescriptionNames": ["audio_1"],
                        "OutputSettings": {"ArchiveOutputSettings": {"ContainerSettings": {"M2tsSettings": {}}}},
                    }
                ],
            }
        ],
        "TimecodeConfig": {"Source": "EMBEDDED"},
    }


def _create_minimal_channel(ctx, name, input_id_a, input_id_b, role_arn, bucket):
    from botocore.exceptions import ClientError

    medialive = ctx.client("medialive")
    hls_input_settings = {
        "NetworkInputSettings": {
            "HlsInputSettings": {"Bandwidth": 2000000, "BufferSegments": 3, "Retries": 3, "RetryInterval": 1}
        }
    }
    create_kwargs = dict(
        Name=name,
        ChannelClass="SINGLE_PIPELINE",
        RoleArn=role_arn,
        InputAttachments=[
            {"InputAttachmentName": "input1", "InputId": input_id_a, "InputSettings": hls_input_settings},
            {"InputAttachmentName": "input2", "InputId": input_id_b, "InputSettings": hls_input_settings},
        ],
        InputSpecification={"Codec": "AVC", "MaximumBitrate": "MAX_10_MBPS", "Resolution": "SD"},
        Destinations=[{"Id": "destination1", "Settings": [{"Url": f"s3://{bucket}/mlout"}]}],
        EncoderSettings=_minimal_encoder_settings(),
        Tags={"sim2real": "channel-schedule-actions-lifecycle"},
    )
    # A freshly created IAM role is not always immediately assumable by MediaLive; retry
    # CreateChannel on a bounded deadline rather than sleeping blind before the first attempt.
    deadline = time.monotonic() + 30.0
    last_err = None
    channel = None
    while time.monotonic() < deadline:
        try:
            channel = medialive.create_channel(**create_kwargs)["Channel"]
            break
        except ClientError as e:
            last_err = e
            time.sleep(5.0)
    if channel is None:
        raise AssertionError(f"create_channel never succeeded waiting for role {role_arn} to propagate: {last_err}")
    ctx.on_cleanup(lambda: _teardown(lambda: _channel_gone_step(medialive, channel["Id"]), 300.0))
    _wait_for_channel_state(ctx, channel["Id"], {"IDLE", "CREATE_FAILED"}, timeout_s=180.0)
    return channel


def _wait_for_channel_state(ctx, channel_id, target_states, timeout_s=180.0, interval_s=5.0):
    medialive = ctx.client("medialive")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = medialive.describe_channel(ChannelId=channel_id)["State"]
        if last in target_states:
            assert last != "CREATE_FAILED", f"channel {channel_id} settled into CREATE_FAILED"
            return last
        time.sleep(interval_s)
    raise AssertionError(f"channel {channel_id} never reached {target_states}, last state={last}")


_GONE = ("NotFoundException", "NoSuchEntity", "NoSuchBucket")


def _teardown(step, timeout_s=120.0):
    """Teardown: call step() every 2 s until it returns anything but False. A not-found code
    means gone, ConflictException (still busy) retries to the deadline, anything else raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            if step() is not False:
                return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in _GONE:
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"teardown did not finish within {timeout_s}s")
        time.sleep(2)


def _channel_gone_step(medialive, channel_id):
    """One teardown step: stop a running channel, delete an idle one; done once DELETED."""
    state = medialive.describe_channel(ChannelId=channel_id)["State"]
    if state == "DELETED":
        return True
    if state == "RUNNING":
        medialive.stop_channel(ChannelId=channel_id)
    elif state in ("IDLE", "CREATE_FAILED", "UPDATE_FAILED"):
        medialive.delete_channel(ChannelId=channel_id)
    return False


def _input_gone_step(medialive, input_id):
    """One teardown step: delete a detached input; done once DELETED."""
    state = medialive.describe_input(InputId=input_id)["State"]
    if state == "DELETED":
        return True
    if state == "DETACHED":
        medialive.delete_input(InputId=input_id)
    return False


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

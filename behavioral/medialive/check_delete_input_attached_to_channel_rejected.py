"""delete-input-attached-to-channel-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-input-attached-to-channel-rejected"
GROUP = "overly-permissive"
SERVICES = ["medialive"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteInput on an input attached to a channel is rejected; detaching (deleting the channel) unblocks it."""
    medialive = ctx.client("medialive")
    role_arn = _iam_role_for_medialive(ctx)
    bucket = _s3_bucket_for_medialive(ctx)
    input_obj = _create_pull_input(ctx, ctx.unique_name("sim2real-medialive-input-"))
    channel = _create_minimal_channel(
        ctx, ctx.unique_name("sim2real-medialive-chan-"), input_obj["Id"], role_arn, bucket
    )
    channel_id = channel["Id"]

    described_input = medialive.describe_input(InputId=input_obj["Id"])
    assert described_input["State"] == "ATTACHED"

    code, message = _client_error(
        lambda: medialive.delete_input(InputId=input_obj["Id"]), "DeleteInput on an input attached to a channel"
    )
    assert code == "ConflictException", code
    assert message == f"Input {input_obj['Id']} is busy, it cannot be deleted", message
    # Effect absent: the input is still there and still attached.
    still_attached = medialive.describe_input(InputId=input_obj["Id"])
    assert still_attached["State"] == "ATTACHED"

    # Positive control: deleting the channel first (detaching the input) lets DeleteInput succeed.
    medialive.delete_channel(ChannelId=channel_id)
    _wait_for_channel_deleted(ctx, channel_id, timeout_s=180.0)
    medialive.delete_input(InputId=input_obj["Id"])
    final = _wait_for_input_deleted(ctx, input_obj["Id"])
    assert final == "DELETED", final


# ===== helpers =====
def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"].get("Code"), e.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to be rejected, but it succeeded: {result!r}")


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
        Tags=[{"Key": "sim2real", "Value": "true"}],
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
    # us-east-1 is CreateBucket's region-pinned default: passing a LocationConstraint there
    # is itself an error, so the literal names that one region, not a hardcoded target.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "true"}]})

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
        Tags={"sim2real": "true"},
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


def _create_minimal_channel(ctx, name, input_id, role_arn, bucket):
    from botocore.exceptions import ClientError

    medialive = ctx.client("medialive")
    kwargs = dict(
        Name=name,
        ChannelClass="SINGLE_PIPELINE",
        RoleArn=role_arn,
        InputAttachments=[{"InputAttachmentName": "input1", "InputId": input_id}],
        InputSpecification={"Codec": "AVC", "MaximumBitrate": "MAX_10_MBPS", "Resolution": "SD"},
        Destinations=[{"Id": "destination1", "Settings": [{"Url": f"s3://{bucket}/mlout"}]}],
        EncoderSettings=_minimal_encoder_settings(),
        Tags={"sim2real": "true"},
    )
    # IAM role trust propagation is eventually consistent: retry CreateChannel, which
    # validates RoleArn up front, until MediaLive stops reporting the role as unusable.
    deadline = time.monotonic() + 60.0
    resp = None
    while resp is None:
        try:
            resp = medialive.create_channel(**kwargs)["Channel"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            # AWS reports a not-yet-propagated role as UnprocessableEntityException naming
            # roleArn, not AccessDenied.
            if code == "UnprocessableEntityException" and "roleArn" in message and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise
    # Registered defensively; the happy path below deletes the channel explicitly.
    ctx.on_cleanup(lambda: _teardown(lambda: _channel_gone_step(medialive, resp["Id"]), 300.0))
    _wait_for_channel_state(ctx, resp["Id"], {"IDLE", "CREATE_FAILED"}, timeout_s=180.0)
    return resp


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


def _wait_for_channel_deleted(ctx, channel_id, timeout_s=180.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    medialive = ctx.client("medialive")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = medialive.describe_channel(ChannelId=channel_id)["State"]
            if last == "DELETED":
                return "DELETED"
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return "NotFoundException"
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"channel {channel_id} was never fully deleted within {timeout_s}s, last={last!r}")


def _wait_for_input_deleted(ctx, input_id, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    medialive = ctx.client("medialive")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = medialive.describe_input(InputId=input_id)["State"]
            if last == "DELETED":
                return "DELETED"
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return "NotFoundException"
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"input {input_id} never reached a deleted terminal state within {timeout_s}s, last={last!r}")


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

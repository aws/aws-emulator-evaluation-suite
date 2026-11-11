"""describe-channel-not-found."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-channel-not-found"
GROUP = "error-semantics"
SERVICES = ["medialive"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeChannel on a channel id that was never created raises NotFoundException; a real channel describes fine."""
    medialive = ctx.client("medialive")

    bogus_id = "999999999"
    code, message = _client_error(
        lambda: medialive.describe_channel(ChannelId=bogus_id), "DescribeChannel on a never-created id"
    )
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == f"Channel {bogus_id} not found", message

    # Positive control: a real channel describes successfully with matching fields.
    role_arn = _iam_role_for_medialive(ctx)
    bucket = _s3_bucket_for_medialive(ctx)
    input_obj = _create_pull_input(ctx, ctx.unique_name("sim2real-medialive-input-"))
    channel = _create_minimal_channel(
        ctx, ctx.unique_name("sim2real-medialive-chan-"), input_obj["Id"], role_arn, bucket
    )
    described = medialive.describe_channel(ChannelId=channel["Id"])
    assert described["Id"] == channel["Id"], f"expected Id {channel['Id']!r}, got {described['Id']!r}"
    assert described["Name"] == channel["Name"], (
        f"expected Name {channel['Name']!r}, got {described['Name']!r}"
    )


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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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
        Tags={"sim2real-owner": "behavioral"},
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
    # IAM role trust propagation is eventually consistent; retry the actual call
    # that depends on it rather than sleeping blind for an arbitrary duration.
    deadline = time.monotonic() + 90.0
    resp = None
    last_err = None
    while time.monotonic() < deadline:
        try:
            resp = medialive.create_channel(
                Name=name,
                ChannelClass="SINGLE_PIPELINE",
                RoleArn=role_arn,
                InputAttachments=[{"InputAttachmentName": "input1", "InputId": input_id}],
                InputSpecification={"Codec": "AVC", "MaximumBitrate": "MAX_10_MBPS", "Resolution": "SD"},
                Destinations=[{"Id": "destination1", "Settings": [{"Url": f"s3://{bucket}/mlout"}]}],
                EncoderSettings=_minimal_encoder_settings(),
                Tags={"sim2real-owner": "behavioral"},
            )["Channel"]
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            # Real MediaLive answers CreateChannel with UnprocessableEntityException
            # (not AccessDeniedException) while the freshly created role has not yet
            # propagated to be assumable by medialive.amazonaws.com.
            if code == "UnprocessableEntityException" and "roleArn" in message:
                last_err = exc
                time.sleep(5)
                continue
            raise
    if resp is None:
        raise AssertionError(f"create_channel never succeeded after role propagation wait: {last_err}")
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

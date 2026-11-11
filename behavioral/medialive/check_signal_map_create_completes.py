"""signal-map-create-completes."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signal-map-create-completes"
GROUP = "state"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateSignalMap discovers a real channel entry point and settles to CREATE_COMPLETE."""
    medialive = ctx.client("medialive")
    role_arn = _iam_role_for_medialive(ctx)
    bucket = _s3_bucket_for_medialive(ctx)
    input_obj = _create_pull_input(ctx, ctx.unique_name("sim2real-medialive-input-"))
    channel = _create_minimal_channel(
        ctx, ctx.unique_name("sim2real-medialive-chan-"), input_obj["Id"], role_arn, bucket
    )

    signal_map = medialive.create_signal_map(
        Name=ctx.unique_name("sim2real-medialive-sigmap-"),
        DiscoveryEntryPointArn=channel["Arn"],
        Tags={"sim2real-env": "test", "sim2real-owner": "medialive-suite"},
    )
    signal_map_id = signal_map["Id"]
    ctx.on_cleanup(lambda: _teardown(lambda: medialive.delete_signal_map(Identifier=signal_map_id)))
    assert signal_map["Status"] in ("CREATE_IN_PROGRESS", "CREATE_COMPLETE")

    final_status = _wait_for_signal_map_status(
        ctx, signal_map_id, {"CREATE_COMPLETE", "CREATE_FAILED"}, timeout_s=240.0
    )
    assert final_status == "CREATE_COMPLETE", f"signal map discovery ended in {final_status}"

    # Independent read, through GetSignalMap rather than the CreateSignalMap response. The
    # meaningful discovery evidence is the traced media resource graph, not an echo of the
    # DiscoveryEntryPointArn we supplied as input — a stub that just parrots the request back
    # would satisfy an echo check without ever discovering anything.
    described = medialive.get_signal_map(Identifier=signal_map_id)
    assert described["DiscoveryEntryPointArn"] == channel["Arn"]
    media_resource_map = described.get("MediaResourceMap") or {}
    assert media_resource_map, f"expected a non-empty discovered media resource map, got {described!r}"
    input_arn = input_obj["Arn"]
    discovered_neighbor_arns = {
        neighbor["Arn"]
        for node in media_resource_map.values()
        for neighbor in (node.get("Sources") or []) + (node.get("Destinations") or [])
    }
    assert input_arn in discovered_neighbor_arns, (
        f"expected discovery starting at channel {channel['Arn']} to trace to its attached "
        f"input {input_arn}; discovered neighbors were {discovered_neighbor_arns}"
    )


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
        Tags=[{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "medialive-suite"}],
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
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "medialive-suite"}]},
    )

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
        Tags={"sim2real-env": "test", "sim2real-owner": "medialive-suite"},
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
        Tags={"sim2real-env": "test", "sim2real-owner": "medialive-suite"},
    )
    # The IAM role we just created is not immediately assumable everywhere — CreateChannel
    # validates RoleArn synchronously and can reject it for a few seconds after CreateRole
    # returns. Bounded retry on that specific rejection, not an unconditional sleep.
    deadline = time.monotonic() + 90.0
    while True:
        try:
            resp = medialive.create_channel(**kwargs)["Channel"]
            break
        except ClientError as exc:
            error = exc.response.get("Error", {})
            message = error.get("Message", "")
            if "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(5.0)
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


def _wait_for_signal_map_status(ctx, signal_map_id, target_statuses, timeout_s=240.0, interval_s=10.0):
    medialive = ctx.client("medialive")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = medialive.get_signal_map(Identifier=signal_map_id)["Status"]
        if last in target_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"signal map {signal_map_id} never reached {target_statuses}, last status={last}")


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

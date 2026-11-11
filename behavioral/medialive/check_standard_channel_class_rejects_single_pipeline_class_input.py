"""standard-channel-class-rejects-single-pipeline-class-input."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "standard-channel-class-rejects-single-pipeline-class-input"
GROUP = "overly-permissive"
SERVICES = ["medialive"]


@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateChannel rejects a STANDARD-class channel attached to a SINGLE_PIPELINE-class input
    (the class an MP4_FILE input with one source always gets); the same input on a
    SINGLE_PIPELINE-class channel (the positive control) still creates successfully.
    """
    from fidelity_tests_runner import require_tools

    require_tools("ffmpeg")

    medialive = ctx.client("medialive")
    bucket = _bucket(ctx)
    _upload_test_clip(ctx, bucket, "source.mp4")
    role_arn = _role(ctx)
    inp = _mp4_file_input(ctx, bucket)
    assert inp["InputClass"] == "SINGLE_PIPELINE", (
        f"a one-source MP4_FILE input should be SINGLE_PIPELINE class, got {inp['InputClass']!r}"
    )

    name = ctx.unique_name("sim2real-ml-chan-")
    code, message = _error(lambda: medialive.create_channel(
        Name=name, ChannelClass="STANDARD", RoleArn=role_arn,
        InputAttachments=[{"InputAttachmentName": "input1", "InputId": inp["Id"],
                            "InputSettings": {"SourceEndBehavior": "LOOP"}}],
        InputSpecification={"Codec": "AVC", "MaximumBitrate": "MAX_10_MBPS", "Resolution": "SD"},
        Destinations=[{"Id": "destination1",
                        "Settings": [{"Url": f"s3://{bucket}/out/stream1"},
                                     {"Url": f"s3://{bucket}/out/stream2"}]}],
        EncoderSettings=_archive_encoder_settings(),
    ))
    assert code == "BadRequestException", (
        f"expected BadRequestException attaching a SINGLE_PIPELINE-class input to a STANDARD "
        f"channel, got {code!r}"
    )
    assert message == (
        f"Input {inp['Id']} has a SINGLE_PIPELINE input class, which is incompatible with a "
        f"STANDARD class channel"
    ), f"unexpected BadRequestException message: {message!r}"

    # Effect absent: no channel with this name was created by the rejected call.
    matches = [c["Name"] for c in _all(ctx, "list_channels", "Channels") if c["Name"] == name]
    assert matches == [], f"a channel named {name!r} exists despite the rejected CreateChannel: {matches!r}"

    # Positive control: the SAME input, role and bucket create a SINGLE_PIPELINE-class channel fine.
    channel = _create_channel(ctx, role_arn, inp["Id"], bucket)
    settled = _wait_for_state(ctx, channel["Id"], {"IDLE", "CREATE_FAILED"}, timeout_s=180.0)
    assert settled == "IDLE", (
        f"the positive-control SINGLE_PIPELINE channel settled into {settled!r}, not IDLE"
    )


# ===== setup helpers =====
def _bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-ml-src-").lower().replace("_", "-")[:63].strip("-")
    kwargs = {"Bucket": name}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for;
    # every other region requires one. Not a resource pin -- a fixed S3 API quirk.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _empty_and_delete() -> None:
        while objs := s3.list_objects_v2(Bucket=name).get("Contents", []):
            for o in objs:
                s3.delete_object(Bucket=name, Key=o["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_teardown(_empty_and_delete, "NoSuchBucket"))
    return name


def _generate_test_clip(path: str) -> None:
    """An 8s 320x240 H.264/AAC MP4 made from synthetic test patterns, no external asset."""
    cmd = [
        "ffmpeg", "-y",
        "-f", "lavfi", "-i", "testsrc=size=320x240:rate=15:duration=8",
        "-f", "lavfi", "-i", "sine=frequency=440:duration=8",
        "-pix_fmt", "yuv420p", "-profile:v", "baseline", "-level", "3.0",
        "-vcodec", "libx264", "-b:v", "300k", "-maxrate", "300k", "-bufsize", "600k", "-g", "30",
        "-acodec", "aac", "-b:a", "64k", "-movflags", "+faststart",
        path,
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert result.returncode == 0, f"ffmpeg failed to generate the test clip: {result.stderr[-800:]}"


def _upload_test_clip(ctx, bucket: str, key: str) -> None:
    s3 = ctx.client("s3")
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "source.mp4")
        _generate_test_clip(path)
        with open(path, "rb") as f:
            data = f.read()
    s3.put_object(Bucket=bucket, Key=key, Body=data, ContentType="video/mp4")
    ctx.on_cleanup(_teardown(lambda: s3.delete_object(Bucket=bucket, Key=key), "NoSuchKey"))


def _trust_policy() -> dict:
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "medialive.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }


def _role(ctx) -> str:
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ml-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_trust_policy()))[
        "Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
    iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    # Registered in this order so LIFO detaches the policy BEFORE deleting the role.
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    ctx.on_cleanup(_teardown(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn),
                             "NoSuchEntity"))
    return arn


def _mp4_file_input(ctx, bucket: str) -> dict:
    medialive = ctx.client("medialive")
    resp = medialive.create_input(
        Name=ctx.unique_name("sim2real-ml-in-"), Type="MP4_FILE",
        Sources=[{"Url": f"s3://{bucket}/source.mp4"}],
    )["Input"]
    ctx.on_cleanup(_teardown(lambda: _delete_input_when_detached(ctx, resp["Id"]),
                             "NotFoundException"))
    return resp


def _delete_input_when_detached(ctx, input_id: str) -> None:
    medialive = ctx.client("medialive")
    deadline = time.monotonic() + 180.0
    while True:
        state = medialive.describe_input(InputId=input_id)["State"]
        if state == "DELETED":
            return
        if state == "DETACHED":
            medialive.delete_input(InputId=input_id)
        if time.monotonic() >= deadline:
            raise AssertionError(f"input {input_id} never reached DELETED (last state {state!r})")
        time.sleep(3)


def _archive_encoder_settings() -> dict:
    return {
        "AudioDescriptions": [
            {"Name": "audio_1", "AudioSelectorName": "default",
             "CodecSettings": {"AacSettings": {"Bitrate": 192000.0, "CodingMode": "CODING_MODE_2_0",
                                                "SampleRate": 48000.0}}},
        ],
        "VideoDescriptions": [
            {"Name": "video_1", "Width": 640, "Height": 360,
             "CodecSettings": {"H264Settings": {
                 "Bitrate": 1000000, "RateControlMode": "CBR", "FramerateControl": "SPECIFIED",
                 "FramerateNumerator": 30, "FramerateDenominator": 1, "GopSize": 90,
                 "GopSizeUnits": "FRAMES", "ParControl": "SPECIFIED", "ParNumerator": 1,
                 "ParDenominator": 1}}},
        ],
        "OutputGroups": [
            {"Name": "group1",
             "OutputGroupSettings": {"ArchiveGroupSettings": {
                 "Destination": {"DestinationRefId": "destination1"},
                 "RolloverInterval": 30}},
             "Outputs": [
                 {"OutputName": "output1", "VideoDescriptionName": "video_1",
                  "AudioDescriptionNames": ["audio_1"],
                  "OutputSettings": {"ArchiveOutputSettings": {
                      "ContainerSettings": {"M2tsSettings": {}}}}},
             ]},
        ],
        "TimecodeConfig": {"Source": "EMBEDDED"},
    }


def _create_channel_with_retry(medialive, kwargs, timeout_s: float = 120.0, interval_s: float = 5.0):
    """CreateChannel, retrying only the just-attached-role-not-yet-assumable rejection."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return medialive.create_channel(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            if "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_channel(ctx, role_arn: str, input_id: str, bucket: str) -> dict:
    medialive = ctx.client("medialive")
    resp = _create_channel_with_retry(medialive, {
        "Name": ctx.unique_name("sim2real-ml-chan-"),
        "ChannelClass": "SINGLE_PIPELINE",
        "RoleArn": role_arn,
        "InputAttachments": [{
            "InputAttachmentName": "input1", "InputId": input_id,
            "InputSettings": {"SourceEndBehavior": "LOOP"},
        }],
        "InputSpecification": {"Codec": "AVC", "MaximumBitrate": "MAX_10_MBPS", "Resolution": "SD"},
        "Destinations": [{"Id": "destination1", "Settings": [{"Url": f"s3://{bucket}/out/stream"}]}],
        "EncoderSettings": _archive_encoder_settings(),
    })["Channel"]
    ctx.on_cleanup(_teardown(lambda: _delete_channel_when_stopped(ctx, resp["Id"]),
                             "NotFoundException"))
    return resp


def _delete_channel_when_stopped(ctx, channel_id: str) -> None:
    medialive = ctx.client("medialive")
    deadline = time.monotonic() + 300.0
    while True:
        state = medialive.describe_channel(ChannelId=channel_id)["State"]
        if state == "DELETED":
            return
        if state == "RUNNING":
            medialive.stop_channel(ChannelId=channel_id)
        elif state in ("IDLE", "CREATE_FAILED", "UPDATE_FAILED"):
            medialive.delete_channel(ChannelId=channel_id)
        if time.monotonic() >= deadline:
            raise AssertionError(f"channel {channel_id} never reached DELETED (last state {state!r})")
        time.sleep(3)


def _wait_for_state(ctx, channel_id: str, target_states: set, timeout_s: float, interval_s: float = 10.0) -> str:
    medialive = ctx.client("medialive")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = medialive.describe_channel(ChannelId=channel_id)["State"]
        if last in target_states:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"channel {channel_id} never reached {target_states}, last state={last!r}")


def _all(ctx, op: str, key: str) -> list:
    """Every item of a paginated MediaLive List* call; the account may hold other channels, so the first page is not enough."""
    out = []
    for page in ctx.client("medialive").get_paginator(op).paginate():
        out.extend(page.get(key) or [])
    return out


def _error(fn) -> tuple[str, str]:
    """(error code, message) ``fn`` raises; an unexpected success raises instead of swallowing it."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded: {result!r}")


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

"""mp4-file-channel-delivers-encoded-segments-to-s3."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "mp4-file-channel-delivers-encoded-segments-to-s3"
GROUP = "data-plane"
SERVICES = ["medialive"]

#: MPEG-TS packets are always 188 bytes starting with the sync byte 0x47.
_TS_SYNC_BYTE = 0x47
_TS_PACKET_SIZE = 188


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A channel reading a real MP4 file writes actual MPEG-TS archive segments to S3 while
    RUNNING, and StopChannel returns it to IDLE with zero running pipelines.
    """
    from fidelity_tests_runner import require_tools

    require_tools("ffmpeg")

    medialive = ctx.client("medialive")
    bucket = _bucket(ctx)
    _upload_test_clip(ctx, bucket, "source.mp4")

    role_arn = _role(ctx, bucket)
    inp = _mp4_file_input(ctx, bucket)
    channel = _create_channel(ctx, role_arn, inp["Id"], bucket)
    channel_id = channel["Id"]

    idle = _wait_for_state(ctx, channel_id, {"IDLE", "CREATE_FAILED"}, timeout_s=180.0)
    assert idle == "IDLE", f"channel settled into {idle!r} instead of IDLE"

    medialive.start_channel(ChannelId=channel_id)
    running = _wait_for_state(ctx, channel_id, {"RUNNING", "CREATE_FAILED"}, timeout_s=300.0)
    assert running == "RUNNING", f"channel entered {running!r} instead of RUNNING"
    started = medialive.describe_channel(ChannelId=channel_id)
    assert started["PipelinesRunningCount"] >= 1, (
        f"expected >=1 running pipeline after StartChannel, got {started['PipelinesRunningCount']!r}"
    )

    key, body = _first_archive_segment(ctx, bucket, "out/", timeout_s=360.0)
    assert len(body) >= _TS_PACKET_SIZE, (
        f"archive segment {key!r} is only {len(body)} byte(s), too small to hold one TS packet"
    )
    assert body[0] == _TS_SYNC_BYTE, (
        f"archive segment {key!r} does not start with the MPEG-TS sync byte 0x47, got {body[0]:#x}"
    )
    second_packet_start = body[_TS_PACKET_SIZE] if len(body) > _TS_PACKET_SIZE else None
    assert second_packet_start == _TS_SYNC_BYTE, (
        f"archive segment {key!r} byte {_TS_PACKET_SIZE} is not a second TS sync byte, "
        f"got {second_packet_start!r}; the channel wrote garbage rather than real MPEG-TS"
    )

    medialive.stop_channel(ChannelId=channel_id)
    stopped_state = _wait_for_state(ctx, channel_id, {"IDLE"}, timeout_s=300.0)
    assert stopped_state == "IDLE", f"channel settled into {stopped_state!r} instead of IDLE after stop"
    stopped = medialive.describe_channel(ChannelId=channel_id)
    assert stopped["PipelinesRunningCount"] == 0, (
        f"expected 0 running pipelines after StopChannel, got {stopped['PipelinesRunningCount']!r}"
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


def _role(ctx, bucket: str) -> str:
    """A role MediaLive assumes to read the source clip from, and write segments to, ``bucket``."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ml-role-")
    arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(_trust_policy()))[
        "Role"]["Arn"]
    policy_name = "sim2real-ml-bucket-access"
    iam.put_role_policy(
        RoleName=name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:ListBucket", "s3:GetBucketLocation"],
                 "Resource": f"arn:aws:s3:::{bucket}"},
                {"Effect": "Allow", "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
                 "Resource": f"arn:aws:s3:::{bucket}/*"},
            ],
        }),
    )
    # Registered in this order so LIFO deletes the inline policy BEFORE deleting the role:
    # IAM refuses to delete a role that still has a policy on it.
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=name), "NoSuchEntity"))
    ctx.on_cleanup(_teardown(lambda: iam.delete_role_policy(RoleName=name, PolicyName=policy_name),
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


def _first_archive_segment(ctx, bucket: str, prefix: str, timeout_s: float, interval_s: float = 5.0):
    """Poll S3 for the first archive object the running channel writes, and return its bytes."""
    s3 = ctx.client("s3")
    deadline = time.monotonic() + timeout_s
    last_count = 0
    while time.monotonic() < deadline:
        objs = s3.list_objects_v2(Bucket=bucket, Prefix=prefix).get("Contents", [])
        last_count = len(objs)
        ready = [o for o in objs if o["Size"] > 0]
        if ready:
            key = ready[0]["Key"]
            body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
            if len(body) > 0:
                return key, body
        time.sleep(interval_s)
    raise AssertionError(
        f"no non-empty archive object appeared under s3://{bucket}/{prefix} within {timeout_s}s "
        f"({last_count} key(s) seen at the last poll)"
    )


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

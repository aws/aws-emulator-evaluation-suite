"""batch-delete-partial-failure."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "batch-delete-partial-failure"
GROUP = "state"
SERVICES = ["medialive"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchDelete partitions a mixed request into Successful and Failed entries."""
    medialive = ctx.client("medialive")
    role_arn = _iam_role_for_medialive(ctx)
    bucket = _s3_bucket_for_medialive(ctx)
    input_a = _create_pull_input(ctx, ctx.unique_name("sim2real-medialive-input-a-"))
    input_b = _create_pull_input(ctx, ctx.unique_name("sim2real-medialive-input-b-"))
    channel_a = _create_minimal_channel(
        ctx, ctx.unique_name("sim2real-medialive-chan-a-"), input_a["Id"], role_arn, bucket
    )
    channel_b = _create_minimal_channel(
        ctx, ctx.unique_name("sim2real-medialive-chan-b-"), input_b["Id"], role_arn, bucket
    )
    bogus_id = "999999999"

    result = medialive.batch_delete(ChannelIds=[channel_a["Id"], channel_b["Id"], bogus_id])

    successful_ids = {item["Id"] for item in result["Successful"]}
    assert successful_ids == {channel_a["Id"], channel_b["Id"]}, successful_ids

    failed_ids = {item["Id"] for item in result["Failed"]}
    assert failed_ids == {bogus_id}, failed_ids
    failed_entry = next(item for item in result["Failed"] if item["Id"] == bogus_id)
    assert failed_entry["Code"] == "NotFoundException", failed_entry
    assert failed_entry["Message"] == f"Channel {bogus_id} not found", failed_entry

    # The two real channels were actually deleted by BatchDelete, not merely reported as such.
    for chan_id in (channel_a["Id"], channel_b["Id"]):
        final = _wait_for_deleted(ctx, lambda cid=chan_id: medialive.describe_channel(ChannelId=cid))
        assert final == "DELETED", f"channel {chan_id} not deleted after BatchDelete: {final}"


# ===== helpers =====
def _wait_for_deleted(ctx, describe_fn, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = describe_fn()
            last = resp.get("State")
            if last == "DELETED":
                return "DELETED"
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NotFoundException":
                return "NotFoundException"
            last = code
        time.sleep(interval_s)
    raise AssertionError(f"resource never reached a deleted terminal state within {timeout_s}s, last={last!r}")


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
        Tags=[{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "behavioral"}],
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
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for;
    # every other region requires one. Not a resource pin — a fixed S3 API quirk.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real-env", "Value": "test"}, {"Key": "sim2real-owner", "Value": "behavioral"}]},
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
        Tags={"sim2real-env": "test", "sim2real-owner": "behavioral"},
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


def _create_channel_with_retry(medialive, kwargs, timeout_s=60.0, interval_s=5.0):
    """CreateChannel, retrying a role-not-yet-assumable rejection.

    IAM role/policy propagation is not instant, and MediaLive validates the role at
    channel-creation time, so a just-attached policy can be rejected for the first few
    seconds. Retrying only that specific rejection is the wait; any other error raises
    immediately.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while True:
        try:
            return medialive.create_channel(**kwargs)
        except ClientError as exc:
            message = exc.response.get("Error", {}).get("Message", "")
            if "role" not in message.lower():
                raise
            last_err = exc
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"CreateChannel never accepted the execution role within {timeout_s}s: {last_err}"
                ) from last_err
            time.sleep(interval_s)


def _create_minimal_channel(ctx, name, input_id, role_arn, bucket):
    medialive = ctx.client("medialive")
    resp = _create_channel_with_retry(
        medialive,
        {
            "Name": name,
            "ChannelClass": "SINGLE_PIPELINE",
            "RoleArn": role_arn,
            "InputAttachments": [{"InputAttachmentName": "input1", "InputId": input_id}],
            "InputSpecification": {"Codec": "AVC", "MaximumBitrate": "MAX_10_MBPS", "Resolution": "SD"},
            "Destinations": [{"Id": "destination1", "Settings": [{"Url": f"s3://{bucket}/mlout"}]}],
            "EncoderSettings": _minimal_encoder_settings(),
            "Tags": {"sim2real-env": "test", "sim2real-owner": "behavioral"},
        },
    )["Channel"]
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

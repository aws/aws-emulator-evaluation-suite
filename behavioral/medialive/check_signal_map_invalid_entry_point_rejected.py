"""signal-map-invalid-entry-point-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signal-map-invalid-entry-point-rejected"
GROUP = "overly-permissive"
SERVICES = ["medialive"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSignalMap with the ARN of a nonexistent channel fails NotFoundException 'Invalid
    discovery-entry-point-arn: Channel 999999999 not found ...' and lists no signal map, while a real
    channel's ARN gives a signal map that reaches CREATE_COMPLETE with that DiscoveryEntryPointArn."""
    medialive = ctx.client("medialive")
    bogus_arn = f"arn:aws:medialive:{ctx.region}:{ctx.account}:channel:999999999"

    code, message = _client_error(
        lambda: medialive.create_signal_map(
            Name=ctx.unique_name("sim2real-medialive-sigmap-bad-"), DiscoveryEntryPointArn=bogus_arn
        ),
        "CreateSignalMap with a bogus discovery entry point",
    )
    assert code == "NotFoundException", f"expected NotFoundException for a bogus entry point, got {code!r}"
    # AWS embeds the request id of its internal downstream call, so only the text around it is fixed.
    prefix = (
        "Invalid discovery-entry-point-arn: Channel 999999999 not found "
        "(Service: MediaLive, Status Code: 404, Request ID: "
    )
    suffix = ") (SDK Attempt Count: 1)"
    assert message.startswith(prefix) and message.endswith(suffix), (
        f"expected message {prefix!r}<request id>{suffix!r}, got {message!r}"
    )
    # Effect absent: no signal map exists with the name we attempted to give the bogus one.
    names = {sm["Name"] for sm in medialive.list_signal_maps()["SignalMaps"]}
    assert all("sim2real-medialive-sigmap-bad-" not in n for n in names), (
        f"bogus signal map name leaked into list_signal_maps: {names}"
    )

    # Positive control: a real channel ARN as the discovery entry point succeeds.
    role_arn = _iam_role_for_medialive(ctx)
    bucket = _s3_bucket_for_medialive(ctx)
    input_obj = _create_pull_input(ctx, ctx.unique_name("sim2real-medialive-input-"))
    channel = _create_minimal_channel(
        ctx, ctx.unique_name("sim2real-medialive-chan-"), input_obj["Id"], role_arn, bucket
    )
    signal_map = medialive.create_signal_map(
        Name=ctx.unique_name("sim2real-medialive-sigmap-ok-"), DiscoveryEntryPointArn=channel["Arn"]
    )
    signal_map_id = signal_map["Id"]
    ctx.on_cleanup(lambda: _teardown(lambda: medialive.delete_signal_map(Identifier=signal_map_id)))
    # Terminal read is independent of the create response: poll get_signal_map (a different
    # operation) to a settled state rather than trusting create_signal_map's own transient status.
    final_status = _wait_for_signal_map_status(
        ctx, signal_map_id, {"CREATE_COMPLETE", "CREATE_FAILED"}, timeout_s=240.0
    )
    assert final_status == "CREATE_COMPLETE", f"signal map discovery ended in {final_status}"
    described = medialive.get_signal_map(Identifier=signal_map_id)
    assert described["DiscoveryEntryPointArn"] == channel["Arn"], (
        f"expected discovery entry point {channel['Arn']!r}, got {described['DiscoveryEntryPointArn']!r}"
    )


# ===== helpers =====
def _gc_stale_medialive(ctx):
    """Free account quota by tearing down sim2real- channels/multiplexes left over from
    previous interrupted runs, before creating new ones."""
    from botocore.exceptions import ClientError

    medialive = ctx.client("medialive")
    try:
        for chan in medialive.list_channels().get("Channels", []):
            name = chan.get("Name", "")
            if not name.startswith("sim2real-"):
                continue
            try:
                if chan.get("State") == "RUNNING":
                    medialive.stop_channel(ChannelId=chan["Id"])
                medialive.delete_channel(ChannelId=chan["Id"])
            except ClientError:
                pass
    except ClientError:
        pass
    try:
        for mux in medialive.list_multiplexes().get("Multiplexes", []):
            name = mux.get("Name", "")
            if not name.startswith("sim2real-"):
                continue
            try:
                medialive.delete_multiplex(MultiplexId=mux["Id"])
            except ClientError:
                pass
    except ClientError:
        pass


def _client_error(fn, description):
    """Call fn() and return its (code, message). An unexpected success raises, so an emulator
    accepting what AWS refuses fails loudly rather than reading as a code mismatch."""
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
    # us-east-1 is S3 CreateBucket's own default region and rejects an explicit
    # LocationConstraint that names it; this is the API's quirk, not an assumed region.
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

    def _attempt():
        return medialive.create_channel(
            Name=name,
            ChannelClass="SINGLE_PIPELINE",
            RoleArn=role_arn,
            InputAttachments=[{"InputAttachmentName": "input1", "InputId": input_id}],
            InputSpecification={"Codec": "AVC", "MaximumBitrate": "MAX_10_MBPS", "Resolution": "SD"},
            Destinations=[{"Id": "destination1", "Settings": [{"Url": f"s3://{bucket}/mlout"}]}],
            EncoderSettings=_minimal_encoder_settings(),
        )["Channel"]

    # A freshly-created IAM role can take a few seconds to propagate before MediaLive can
    # assume it; retry the create call itself (a genuine wait on real asynchrony) rather than
    # sleeping blindly before the first attempt. Real AWS raises UnprocessableEntityException
    # with "roleArn Make sure the role ... exists ... and medialive.amazonaws.com is a trusted
    # service" while that propagation is in flight.
    deadline = time.monotonic() + 60.0
    resp = None
    while resp is None:
        try:
            resp = _attempt()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            msg = e.response["Error"].get("Message", "")
            if time.monotonic() >= deadline or code != "UnprocessableEntityException" or "role" not in msg.lower():
                raise
            time.sleep(3.0)
    ctx.on_cleanup(lambda: _teardown(lambda: _channel_gone_step(medialive, resp["Id"]), 300.0))
    _wait_for_channel_state(ctx, resp["Id"], {"IDLE", "CREATE_FAILED"}, timeout_s=180.0)
    return resp


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

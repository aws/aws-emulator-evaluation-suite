"""channel-not-broadcasting-across-operations."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-not-broadcasting-across-operations"
GROUP = "error-semantics"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """On a channel with no active stream, GetStream, InsertAdBreak (with an ad configuration attached), PutMetadata
    and StopStream all fail ChannelNotBroadcasting with the exact message."""
    ivs = ctx.client("ivs")
    mediatailor = ctx.client("mediatailor")
    ad_arn = _create_ad_configuration(ctx, ivs, mediatailor)

    name = ctx.unique_name("sim2real-ivs-offline-")
    arn = ivs.create_channel(
        name=name,
        type="STANDARD",
        adConfigurationArn=ad_arn,
        tags={"purpose": "sim2real"},
    )["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    expected = f"Channel: {arn} is not currently online"
    for op, call in (
        ("GetStream", lambda: ivs.get_stream(channelArn=arn)),
        ("InsertAdBreak", lambda: ivs.insert_ad_break(channelArn=arn, durationSeconds=30)),
        ("PutMetadata", lambda: ivs.put_metadata(channelArn=arn, metadata="hello")),
        ("StopStream", lambda: ivs.stop_stream(channelArn=arn)),
    ):
        err = _client_error(call)
        assert err["Code"] == "ChannelNotBroadcasting", (
            f"{op} on an idle channel returned {err!r}, expected ChannelNotBroadcasting"
        )
        assert err["Message"] == expected, (
            f"{op} on an idle channel returned message {err['Message']!r}, expected {expected!r}"
        )


def _create_ad_configuration(ctx, ivs, mediatailor) -> str:
    """IVS SSAI requires the MediaTailor playback config's VideoContentSourceUrl to be
    the account/region-wide IVS playback URL prefix (everything before '/api/'), and
    InsertionMode=PLAYER_SELECT. Spin up a throwaway channel just to read that prefix
    off its playbackUrl, then wire a real ad configuration from it."""
    probe_name = ctx.unique_name("sim2real-ivs-prefix-probe-")
    probe_channel = ivs.create_channel(name=probe_name, tags={"purpose": "sim2real"})["channel"]
    try:
        prefix = probe_channel["playbackUrl"].split("/api/")[0] + "/"
    finally:
        ivs.delete_channel(arn=probe_channel["arn"])

    mt_name = ctx.unique_name("sim2real-ivs-mt-")
    mt_arn = mediatailor.put_playback_configuration(
        Name=mt_name,
        AdDecisionServerUrl="https://example.com/ads?abc={aws.random}",
        VideoContentSourceUrl=prefix,
        InsertionMode="PLAYER_SELECT",
        Tags={"purpose": "sim2real"},
    )["PlaybackConfigurationArn"]
    ctx.on_cleanup(lambda: mediatailor.delete_playback_configuration(Name=mt_name))

    ad_name = ctx.unique_name("sim2real-ivs-ad-")
    ad_arn = ivs.create_ad_configuration(
        name=ad_name,
        mediaTailorPlaybackConfigurations=[{"playbackConfigurationArn": mt_arn}],
        tags={"purpose": "sim2real"},
    )["adConfiguration"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_ad_configuration(arn=ad_arn))
    return ad_arn


def _client_error(fn):
    """Call fn(); return its botocore error. An unexpected SUCCESS raises, because a target
    accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(
        f"expected the call to be rejected with ChannelNotBroadcasting, but it succeeded "
        f"and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


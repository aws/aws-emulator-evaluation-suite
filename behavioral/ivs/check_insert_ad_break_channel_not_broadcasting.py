"""insert-ad-break-channel-not-broadcasting."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "insert-ad-break-channel-not-broadcasting"
GROUP = "errors"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """InsertAdBreak on a channel with a valid ad configuration that is not live fails ChannelNotBroadcasting with
    the exact "is not currently online" message."""
    ivs = ctx.client("ivs")
    mediatailor = ctx.client("mediatailor")

    ad_arn = _create_ad_configuration(ctx, ivs, mediatailor)

    name = ctx.unique_name("sim2real-ivs-chan-")
    arn = ivs.create_channel(
        name=name, adConfigurationArn=ad_arn, tags={"purpose": "sim2real"}
    )["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    error = _error(lambda: ivs.insert_ad_break(channelArn=arn, durationSeconds=30))
    assert error["Code"] == "ChannelNotBroadcasting", (
        f"expected ChannelNotBroadcasting on a channel with no active stream, got {error['Code']!r}"
    )
    assert error["Message"] == f"Channel: {arn} is not currently online", repr(error["Message"])


def _create_ad_configuration(ctx, ivs, mediatailor) -> str:
    """IVS SSAI requires the MediaTailor playback config's VideoContentSourceUrl to be
    the account/region-wide IVS playback URL prefix (everything before '/api/'), and
    InsertionMode=PLAYER_SELECT. Spin up a throwaway channel just to read that prefix
    off its playbackUrl, then wire a real ad configuration from it."""
    probe_name = ctx.unique_name("sim2real-ivs-prefix-probe-")
    probe_channel = ivs.create_channel(
        name=probe_name, tags={"purpose": "sim2real"}
    )["channel"]
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


def _error(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


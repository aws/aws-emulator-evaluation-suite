"""delete-ad-configuration-associated-with-channel-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "delete-ad-configuration-associated-with-channel-rejected"
GROUP = "error-semantics"
SERVICES = ["ivs"]


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAdConfiguration on an ad configuration a channel references fails ConflictException with the exact
    message and it survives; an unreferenced one deletes, and after the channel is deleted so does this one."""
    ivs = ctx.client("ivs")
    mediatailor = ctx.client("mediatailor")

    prefix = _ivs_playback_url_prefix(ctx, ivs)

    mt_name = ctx.unique_name("sim2real-ivs-mt-")
    mt_arn = mediatailor.put_playback_configuration(
        Name=mt_name,
        AdDecisionServerUrl="https://example.com/ads?abc={aws.random}",
        VideoContentSourceUrl=prefix,
        InsertionMode="PLAYER_SELECT",
        Tags={"sim2real": CHECK},
    )["PlaybackConfigurationArn"]
    ctx.on_cleanup(lambda: mediatailor.delete_playback_configuration(Name=mt_name))

    # Positive control: DeleteAdConfiguration on an ad configuration with no channel
    # reference succeeds. Without this, the ConflictException below is indistinguishable
    # from "this account/credentials reject every DeleteAdConfiguration call".
    control_name = ctx.unique_name("sim2real-ivs-ad-ctl-")
    control_arn = ivs.create_ad_configuration(
        name=control_name,
        mediaTailorPlaybackConfigurations=[{"playbackConfigurationArn": mt_arn}],
        tags={"sim2real": CHECK},
    )["adConfiguration"]["arn"]
    ivs.delete_ad_configuration(arn=control_arn)
    control_after = _client_error(lambda: ivs.get_ad_configuration(arn=control_arn))
    assert control_after["Code"] == "ResourceNotFoundException", (
        f"positive control: deleting an unreferenced ad configuration must succeed and "
        f"leave it not-found; get_ad_configuration afterwards returned {control_after!r}"
    )
    assert control_after["Message"] == f"Resource: {control_arn} not found", (
        f"unexpected GetAdConfiguration not-found message: {control_after['Message']!r}"
    )

    ad_name = ctx.unique_name("sim2real-ivs-ad-")
    ad_config = ivs.create_ad_configuration(
        name=ad_name,
        mediaTailorPlaybackConfigurations=[{"playbackConfigurationArn": mt_arn}],
        tags={"sim2real": CHECK},
    )["adConfiguration"]
    ad_arn = ad_config["arn"]

    chan_name = ctx.unique_name("sim2real-ivs-ad-chan-")
    channel = ivs.create_channel(
        name=chan_name, adConfigurationArn=ad_arn, tags={"sim2real": CHECK}
    )["channel"]
    chan_arn = channel["arn"]
    ctx.on_cleanup(lambda: _safe_delete(ivs.delete_channel, arn=chan_arn))
    ctx.on_cleanup(lambda: _safe_delete(ivs.delete_ad_configuration, arn=ad_arn))

    error = _client_error(lambda: ivs.delete_ad_configuration(arn=ad_arn))
    assert error["Code"] == "ConflictException", (
        f"DeleteAdConfiguration on an ad configuration still referenced by a channel "
        f"must be rejected with ConflictException; got {error!r}"
    )
    assert error["Message"] == (
        f"Unable to perform ivs:DeleteAdConfiguration while ad configuration {ad_arn} "
        f"is still attached to a channel"
    ), f"unexpected DeleteAdConfiguration conflict message: {error['Message']!r}"

    still_there = ivs.get_ad_configuration(arn=ad_arn)["adConfiguration"]
    assert still_there["arn"] == ad_arn, (
        f"the ad configuration must survive the rejected delete; expected arn {ad_arn!r}, "
        f"got {still_there['arn']!r}"
    )

    # Restore: detach then the identical delete call succeeds.
    ivs.delete_channel(arn=chan_arn)
    ivs.delete_ad_configuration(arn=ad_arn)
    after = _client_error(lambda: ivs.get_ad_configuration(arn=ad_arn))
    assert after["Code"] == "ResourceNotFoundException", (
        f"once detached, the identical delete must succeed and the ad configuration must "
        f"be gone; get_ad_configuration afterwards returned {after!r}"
    )
    assert after["Message"] == f"Resource: {ad_arn} not found", (
        f"unexpected GetAdConfiguration not-found message: {after['Message']!r}"
    )


def _safe_delete(fn, **kwargs) -> None:
    from botocore.exceptions import ClientError

    try:
        fn(**kwargs)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _ivs_playback_url_prefix(ctx, ivs) -> str:
    """IVS SSAI requires the MediaTailor playback config's VideoContentSourceUrl to be
    the account/region-wide IVS playback URL prefix (everything before '/api/').
    Spin up a throwaway channel just to read that prefix off its playbackUrl."""
    probe_name = ctx.unique_name("sim2real-ivs-prefix-probe-")
    channel = ivs.create_channel(name=probe_name, tags={"sim2real": CHECK})["channel"]
    try:
        playback_url = channel["playbackUrl"]
        return playback_url.split("/api/")[0] + "/"
    finally:
        ivs.delete_channel(arn=channel["arn"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

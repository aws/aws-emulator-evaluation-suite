"""create-ad-configuration-empty-list-rejected."""
from __future__ import annotations

from botocore.config import Config

from behavioral_harness import tags

CHECK = "create-ad-configuration-empty-list-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(
        f"expected create_ad_configuration to be rejected, but it succeeded: {result!r}"
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAdConfiguration with an empty mediaTailorPlaybackConfigurations list fails ValidationException with the
    exact message and creates nothing, while one real MediaTailor playback configuration round-trips its ARN."""
    ivs = ctx.client("ivs")
    mediatailor = ctx.client("mediatailor")

    prefix = _ivs_playback_url_prefix(ctx, ivs)

    mt_name = ctx.unique_name("sim2real-ivs-mt-")
    mt_config = mediatailor.put_playback_configuration(
        Name=mt_name,
        AdDecisionServerUrl="https://example.com/ads?abc={aws.random}",
        VideoContentSourceUrl=prefix,
        InsertionMode="PLAYER_SELECT",
        Tags={"purpose": "sim2real"},
    )
    mt_arn = mt_config["PlaybackConfigurationArn"]
    ctx.on_cleanup(lambda: mediatailor.delete_playback_configuration(Name=mt_name))

    # botocore's own shape validator rejects an empty mediaTailorPlaybackConfigurations
    # list locally (length min:1 is baked into the generated model) before the request
    # ever leaves the process; disable client-side param validation so the request
    # actually reaches the service and we observe *its* rejection, not the SDK's.
    bad_name = ctx.unique_name("sim2real-ivs-ad-bad-")
    raw_ivs = ctx.client("ivs", config=Config(parameter_validation=False))
    error = _client_error(
        lambda: raw_ivs.create_ad_configuration(
            name=bad_name, mediaTailorPlaybackConfigurations=[]
        )
    )
    assert error["Code"] == "ValidationException", error
    assert error["Message"] == (
        "CreateAdConfiguration.mediaTailorPlaybackConfigurations is required to have a "
        "minimum length of 1, found 0"
    ), error

    found = [c for c in ivs.list_ad_configurations()["adConfigurations"] if c["name"] == bad_name]
    assert found == [], found

    good_name = ctx.unique_name("sim2real-ivs-ad-good-")
    created = ivs.create_ad_configuration(
        name=good_name,
        mediaTailorPlaybackConfigurations=[{"playbackConfigurationArn": mt_arn}],
        tags={"purpose": "sim2real"},
    )["adConfiguration"]
    created_arn = created["arn"]
    ctx.on_cleanup(lambda: ivs.delete_ad_configuration(arn=created_arn))

    fetched = ivs.get_ad_configuration(arn=created_arn)["adConfiguration"]
    assert fetched["name"] == good_name, fetched
    assert len(fetched["mediaTailorPlaybackConfigurations"]) == 1, fetched
    assert (
        fetched["mediaTailorPlaybackConfigurations"][0]["playbackConfigurationArn"] == mt_arn
    ), fetched


def _ivs_playback_url_prefix(ctx, ivs) -> str:
    """IVS SSAI requires the MediaTailor playback config's VideoContentSourceUrl to be
    the account/region-wide IVS playback URL prefix (everything before '/api/').
    Spin up a throwaway channel just to read that prefix off its playbackUrl."""
    probe_name = ctx.unique_name("sim2real-ivs-prefix-probe-")
    channel = ivs.create_channel(name=probe_name, tags={"purpose": "sim2real"})["channel"]
    try:
        playback_url = channel["playbackUrl"]
        return playback_url.split("/api/")[0] + "/"
    finally:
        ivs.delete_channel(arn=channel["arn"])


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

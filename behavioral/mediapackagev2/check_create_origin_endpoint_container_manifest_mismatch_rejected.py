"""create-origin-endpoint-container-manifest-mismatch-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-origin-endpoint-container-manifest-mismatch-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]

_TAGS = {"sim2real-check": "create-origin-endpoint-container-manifest-mismatch-rejected"}


def _client_error(fn):
    """Call fn(); return its full botocore response (Error dict plus any modeled exception members,
    e.g. ValidationExceptionType, which ride alongside "Error" at the top level, not inside it). An
    unexpected SUCCESS raises, because an emulator ACCEPTING input real AWS refuses is the strongest
    signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A TS container endpoint with a DASH manifest is rejected (TS_CONTAINER_TYPE_WITH_DASH_MANIFEST)."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    bad_endpoint = ctx.unique_name("sim2real-mpv2-oe-bad-")
    good_endpoint = ctx.unique_name("sim2real-mpv2-oe-good-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))

    err = _client_error(
        lambda: mp.create_origin_endpoint(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=bad_endpoint,
            ContainerType="TS",
            DashManifests=[{"ManifestName": "dash1"}],
        )
    )
    assert err["Error"].get("Code") == "ValidationException", f"expected ValidationException, got {err}"
    assert err["Error"].get("Message") == (
        "Validation error encountered at request: DASH manifest is not supported on endpoint "
        "with TS container type. "
    ), f"got {err}"
    assert err.get("ValidationExceptionType") == "TS_CONTAINER_TYPE_WITH_DASH_MANIFEST", (
        f"expected ValidationExceptionType=TS_CONTAINER_TYPE_WITH_DASH_MANIFEST, got {err}"
    )

    # Effect absent: the endpoint was never created (independent read at the destination).
    not_found = _client_error(
        lambda: mp.get_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=bad_endpoint
        )
    )
    assert not_found["Error"].get("Code") == "ResourceNotFoundException", (
        f"expected the rejected endpoint to not exist, got {not_found}"
    )
    assert not_found["Error"].get("Message") == (
        "MediaPackage can't process your request because we can't find your origin endpoint. "
        "Verify your origin endpoint name or add an origin endpoint and then try again"
    ), f"got {not_found}"

    # Positive control: TS container with a compatible HLS manifest succeeds.
    mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=good_endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags=_TAGS,
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=good_endpoint
        )
    )
    ok = mp.get_origin_endpoint(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=good_endpoint
    )
    assert ok["ContainerType"] == "TS", f"expected ContainerType=TS, got {ok.get('ContainerType')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

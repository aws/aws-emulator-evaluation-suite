"""create-origin-endpoint-num-manifests-low-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-origin-endpoint-num-manifests-low-rejected"
GROUP = "overly-permissive"
SERVICES = ["mediapackagev2"]


_NO_MANIFEST = (
    "Validation error encountered at request: You've requested an origin endpoint without a "
    "manifest. Your origin endpoint needs to contain at least one manifest. Add a manifest and "
    "try to create your origin endpoint again"
)
_ORIGIN_ENDPOINT_NOT_FOUND = (
    "MediaPackage can't process your request because we can't find your origin endpoint. "
    "Verify your origin endpoint name or add an origin endpoint and then try again"
)


def _error(fn):
    """Call fn(); return its error (Code and Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOriginEndpoint with ContainerType=TS and no manifest entries fails ValidationException with the
    exact message and creates no endpoint, while the same request with an HLS manifest 'index' is created
    and read back."""
    mp = ctx.client("mediapackagev2")
    group = ctx.unique_name("sim2real-mpkg-cg-")
    channel = ctx.unique_name("sim2real-mpkg-ch-")
    mp.create_channel_group(ChannelGroupName=group, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group))
    mp.create_channel(ChannelGroupName=group, ChannelName=channel, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group, ChannelName=channel))

    bad_endpoint = ctx.unique_name("sim2real-mpkg-oe-bad-")
    err = _error(
        lambda: mp.create_origin_endpoint(
            ChannelGroupName=group,
            ChannelName=channel,
            OriginEndpointName=bad_endpoint,
            ContainerType="TS",
        )
    )
    assert err["Code"] == "ValidationException", f"expected ValidationException for a zero-manifest TS endpoint, got {err!r}"
    assert err["Message"] == _NO_MANIFEST, f"got {err!r}"

    err_after = _error(
        lambda: mp.get_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=bad_endpoint
        )
    )
    assert err_after["Code"] == "ResourceNotFoundException", (
        f"expected the rejected endpoint to never exist, got {err_after!r} reading it back"
    )
    assert err_after["Message"] == _ORIGIN_ENDPOINT_NOT_FOUND, f"got {err_after!r}"

    # Positive control: attaching an HLS manifest satisfies the minimum-manifest rule.
    good_endpoint = ctx.unique_name("sim2real-mpkg-oe-good-")
    created = mp.create_origin_endpoint(
        ChannelGroupName=group,
        ChannelName=channel,
        OriginEndpointName=good_endpoint,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        Tags={"sim2real": "true"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group, ChannelName=channel, OriginEndpointName=good_endpoint
        )
    )
    assert created["HlsManifests"][0]["ManifestName"] == "index", (
        f"expected the create response to echo the HLS manifest, got {created.get('HlsManifests')!r}"
    )

    # Terminal read: independent of the mutating CreateOriginEndpoint call above.
    read_back = mp.get_origin_endpoint(
        ChannelGroupName=group, ChannelName=channel, OriginEndpointName=good_endpoint
    )
    assert read_back["HlsManifests"][0]["ManifestName"] == "index", (
        f"expected an independent read of the good endpoint to show the HLS manifest, "
        f"got {read_back.get('HlsManifests')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

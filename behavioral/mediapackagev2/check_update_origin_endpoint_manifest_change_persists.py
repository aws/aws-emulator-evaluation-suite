"""update-origin-endpoint-manifest-change-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-origin-endpoint-manifest-change-persists"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOriginEndpoint with a new ManifestWindowSeconds on the HLS manifest
    persists: GetOriginEndpoint reflects the new value and the ETag rotates."""
    mp = ctx.client("mediapackagev2")
    check_tags = {"sim2real-check": CHECK}

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(ChannelGroupName=group_name, Tags=check_tags)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name, Tags=check_tags)
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )

    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")
    created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 60}],
        Tags=check_tags,
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )
    old_etag = created["ETag"]
    assert created["HlsManifests"][0]["ManifestWindowSeconds"] == 60, (
        f"expected ManifestWindowSeconds=60 on create, got "
        f"{created['HlsManifests'][0]['ManifestWindowSeconds']}"
    )

    updated = mp.update_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 120}],
        ETag=old_etag,
    )
    assert updated["HlsManifests"][0]["ManifestWindowSeconds"] == 120, (
        f"expected ManifestWindowSeconds=120 in the update response, got "
        f"{updated['HlsManifests'][0]['ManifestWindowSeconds']}"
    )
    new_etag = updated["ETag"]
    assert new_etag != old_etag, "ETag did not rotate after a successful update"

    got = mp.get_origin_endpoint(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )
    assert got["HlsManifests"][0]["ManifestWindowSeconds"] == 120, (
        f"expected the independent GetOriginEndpoint read to reflect ManifestWindowSeconds=120, "
        f"got {got['HlsManifests'][0]['ManifestWindowSeconds']}"
    )
    assert got["ETag"] == new_etag, (
        f"expected GetOriginEndpoint to reflect the rotated ETag {new_etag!r}, got {got['ETag']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

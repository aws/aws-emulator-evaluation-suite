"""update-origin-endpoint-startover-window-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-origin-endpoint-startover-window-persists"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateOriginEndpoint's StartoverWindowSeconds change persists and rotates the ETag."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_name = ctx.unique_name("sim2real-mpv2-oe-")

    mp.create_channel_group(ChannelGroupName=group_name)
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))
    created = mp.create_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        StartoverWindowSeconds=60,
    )
    ctx.on_cleanup(
        lambda: mp.delete_origin_endpoint(
            ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
        )
    )
    assert created["StartoverWindowSeconds"] == 60, (
        f"expected StartoverWindowSeconds=60 on create, got {created['StartoverWindowSeconds']!r}"
    )

    updated = mp.update_origin_endpoint(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        OriginEndpointName=endpoint_name,
        ContainerType="TS",
        HlsManifests=[{"ManifestName": "index"}],
        StartoverWindowSeconds=300,
        ETag=created["ETag"],
    )
    assert updated["StartoverWindowSeconds"] == 300, (
        f"expected StartoverWindowSeconds=300 after update, got {updated['StartoverWindowSeconds']!r}"
    )
    assert updated["ETag"] != created["ETag"], (
        f"expected ETag to rotate after update, got unchanged {updated['ETag']!r}"
    )

    fetched = mp.get_origin_endpoint(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_name
    )
    assert fetched["StartoverWindowSeconds"] == 300, (
        f"expected GetOriginEndpoint to reflect StartoverWindowSeconds=300, got {fetched['StartoverWindowSeconds']!r}"
    )
    assert fetched["ETag"] == updated["ETag"], (
        f"expected GetOriginEndpoint ETag to match update response {updated['ETag']!r}, got {fetched['ETag']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

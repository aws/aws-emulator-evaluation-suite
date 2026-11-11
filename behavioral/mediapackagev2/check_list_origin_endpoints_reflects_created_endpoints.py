"""list-origin-endpoints-reflects-created-endpoints."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-origin-endpoints-reflects-created-endpoints"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOriginEndpoints returns exactly the origin endpoints created under a fresh channel."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    endpoint_a = ctx.unique_name("sim2real-mpv2-oe-a-")
    endpoint_b = ctx.unique_name("sim2real-mpv2-oe-b-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real:managed": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    mp.create_channel(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        Tags={"sim2real:managed": "true"},
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))

    for name in (endpoint_a, endpoint_b):
        mp.create_origin_endpoint(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=name,
            ContainerType="TS",
            HlsManifests=[{"ManifestName": "index"}],
            Tags={"sim2real:managed": "true"},
        )
        ctx.on_cleanup(
            lambda n=name: mp.delete_origin_endpoint(
                ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=n
            )
        )

    listed = mp.list_origin_endpoints(ChannelGroupName=group_name, ChannelName=channel_name)
    listed_names = {item["OriginEndpointName"] for item in listed["Items"]}
    assert listed_names == {endpoint_a, endpoint_b}, (
        f"expected exactly {{{endpoint_a!r}, {endpoint_b!r}}}, got {listed_names!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

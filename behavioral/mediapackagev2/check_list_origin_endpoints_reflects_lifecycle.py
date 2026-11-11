"""list-origin-endpoints-reflects-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-origin-endpoints-reflects-lifecycle"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOriginEndpoints includes every OriginEndpoint created under a Channel and
    stops including one as soon as it's deleted."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    mp.create_channel_group(
        ChannelGroupName=group_name, Tags={"sim2real-key": "sim2real-value"}
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    channel_name = ctx.unique_name("sim2real-mpv2-ch-")
    mp.create_channel(
        ChannelGroupName=group_name,
        ChannelName=channel_name,
        Tags={"sim2real-key": "sim2real-value"},
    )
    ctx.on_cleanup(
        lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    )

    endpoint_a = ctx.unique_name("sim2real-mpv2-oe-a-")
    endpoint_b = ctx.unique_name("sim2real-mpv2-oe-b-")
    for name in (endpoint_a, endpoint_b):
        mp.create_origin_endpoint(
            ChannelGroupName=group_name,
            ChannelName=channel_name,
            OriginEndpointName=name,
            ContainerType="TS",
            HlsManifests=[{"ManifestName": "index", "ManifestWindowSeconds": 60}],
            Tags={"sim2real-key": "sim2real-value"},
        )
        ctx.on_cleanup(
            lambda name=name: mp.delete_origin_endpoint(
                ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=name
            )
        )

    names = {
        e["OriginEndpointName"]
        for e in mp.list_origin_endpoints(
            ChannelGroupName=group_name, ChannelName=channel_name
        )["Items"]
    }
    assert endpoint_a in names, f"{endpoint_a} missing from ListOriginEndpoints: {names}"
    assert endpoint_b in names, f"{endpoint_b} missing from ListOriginEndpoints: {names}"

    mp.delete_origin_endpoint(
        ChannelGroupName=group_name, ChannelName=channel_name, OriginEndpointName=endpoint_b
    )
    names_after = {
        e["OriginEndpointName"]
        for e in mp.list_origin_endpoints(
            ChannelGroupName=group_name, ChannelName=channel_name
        )["Items"]
    }
    assert endpoint_a in names_after, f"{endpoint_a} unexpectedly disappeared: {names_after}"
    assert endpoint_b not in names_after, f"{endpoint_b} still listed after delete: {names_after}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

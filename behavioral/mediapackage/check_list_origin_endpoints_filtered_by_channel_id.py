"""list-origin-endpoints-filtered-by-channel-id."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-origin-endpoints-filtered-by-channel-id"
GROUP = "state"
SERVICES = ["mediapackage"]


def _create_channel_and_endpoint(ctx):
    mp = ctx.client("mediapackage")
    resource_tags = {"created-by": "sim2real"}
    channel_id = ctx.unique_name("sim2real-mp-ch-")
    mp.create_channel(Id=channel_id, Tags=resource_tags)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    origin_id = ctx.unique_name("sim2real-mp-oe-")
    mp.create_origin_endpoint(Id=origin_id, ChannelId=channel_id, HlsPackage={}, Tags=resource_tags)

    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=origin_id))
    return channel_id, origin_id


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListOriginEndpoints filtered by ChannelId returns only that channel's
    endpoints, excluding origin endpoints that belong to a different channel."""
    mp = ctx.client("mediapackage")

    channel_a, origin_a = _create_channel_and_endpoint(ctx)
    channel_b, origin_b = _create_channel_and_endpoint(ctx)

    resp_a = mp.list_origin_endpoints(ChannelId=channel_a)
    ids_a = [e["Id"] for e in resp_a.get("OriginEndpoints", [])]
    assert origin_a in ids_a, f"expected {origin_a} in channel {channel_a}'s endpoints, got {ids_a}"
    assert origin_b not in ids_a, (
        f"endpoint {origin_b} from channel {channel_b} leaked into channel {channel_a}'s list: {ids_a}"
    )

    resp_b = mp.list_origin_endpoints(ChannelId=channel_b)
    ids_b = [e["Id"] for e in resp_b.get("OriginEndpoints", [])]
    assert origin_b in ids_b, f"expected {origin_b} in channel {channel_b}'s endpoints, got {ids_b}"
    assert origin_a not in ids_b, (
        f"endpoint {origin_a} from channel {channel_a} leaked into channel {channel_b}'s list: {ids_b}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

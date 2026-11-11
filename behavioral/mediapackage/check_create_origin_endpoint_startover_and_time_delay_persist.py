"""create-origin-endpoint-startover-and-time-delay-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-origin-endpoint-startover-and-time-delay-persist"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartoverWindowSeconds=3600 and TimeDelaySeconds=30 given to CreateOriginEndpoint come back exactly
    in the create response and in DescribeOriginEndpoint: they size the startover window and on-air delay."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    mp.create_channel(Id=channel_id)
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-ep-")
    created = mp.create_origin_endpoint(
        Id=endpoint_id,
        ChannelId=channel_id,
        StartoverWindowSeconds=3600,
        TimeDelaySeconds=30,
        HlsPackage={"SegmentDurationSeconds": 6},
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))

    assert created["StartoverWindowSeconds"] == 3600, (
        f"expected StartoverWindowSeconds=3600 on create, got {created['StartoverWindowSeconds']!r}"
    )
    assert created["TimeDelaySeconds"] == 30, (
        f"expected TimeDelaySeconds=30 on create, got {created['TimeDelaySeconds']!r}"
    )

    described = mp.describe_origin_endpoint(Id=endpoint_id)
    assert described["StartoverWindowSeconds"] == 3600, (
        "StartoverWindowSeconds was not persisted across a Describe call"
    )
    assert described["TimeDelaySeconds"] == 30, (
        "TimeDelaySeconds was not persisted across a Describe call"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

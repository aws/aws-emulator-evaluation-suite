"""create-origin-endpoint-default-origination-is-allow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-origin-endpoint-default-origination-is-allow"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """When Origination is omitted at CreateOriginEndpoint time, the endpoint
    defaults to ALLOW (new playback sessions are not blocked out of the box)."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    mp.create_channel(Id=channel_id, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-ep-")
    created = mp.create_origin_endpoint(
        Id=endpoint_id,
        ChannelId=channel_id,
        HlsPackage={"SegmentDurationSeconds": 6},
        Tags={"created-by": "sim2real"},
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))

    assert created["Origination"] == "ALLOW", (
        f"expected default Origination to be ALLOW, got {created['Origination']!r}"
    )
    described = mp.describe_origin_endpoint(Id=endpoint_id)
    assert described["Origination"] == "ALLOW", (
        f"expected described Origination to remain ALLOW, got {described['Origination']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

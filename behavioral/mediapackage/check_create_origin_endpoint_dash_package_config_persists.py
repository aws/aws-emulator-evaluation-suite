"""create-origin-endpoint-dash-package-config-persists."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-origin-endpoint-dash-package-config-persists"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A non-default DashPackage configuration passed to CreateOriginEndpoint is
    persisted exactly and readable via DescribeOriginEndpoint."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    mp.create_channel(Id=channel_id, Tags={"created-by": "sim2real"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-ep-")
    dash_package = {
        "ManifestWindowSeconds": 90,
        "MinBufferTimeSeconds": 5,
        "MinUpdatePeriodSeconds": 3,
        "SuggestedPresentationDelaySeconds": 10,
        "Profile": "NONE",
    }
    created = mp.create_origin_endpoint(
        Id=endpoint_id,
        ChannelId=channel_id,
        DashPackage=dash_package,
        Tags={"created-by": "sim2real"},
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))

    got = created["DashPackage"]
    assert got["ManifestWindowSeconds"] == 90
    assert got["MinBufferTimeSeconds"] == 5
    assert got["MinUpdatePeriodSeconds"] == 3
    assert got["SuggestedPresentationDelaySeconds"] == 10

    described = mp.describe_origin_endpoint(Id=endpoint_id)
    assert described["DashPackage"]["ManifestWindowSeconds"] == 90
    assert described["DashPackage"]["MinBufferTimeSeconds"] == 5


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

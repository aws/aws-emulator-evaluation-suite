"""create-origin-endpoint-cmaf-segment-prefix-defaults-to-channel-id."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-origin-endpoint-cmaf-segment-prefix-defaults-to-channel-id"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CmafPackage.SegmentPrefix, when not explicitly supplied, defaults to the
    Channel's Id (per the API's documented default), not to an empty value or the
    OriginEndpoint's own Id."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    mp.create_channel(Id=channel_id, Tags={"sim2real": "true"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))

    endpoint_id = ctx.unique_name("sim2real-mp-ep-")
    created = mp.create_origin_endpoint(
        Id=endpoint_id,
        ChannelId=channel_id,
        CmafPackage={
            "SegmentDurationSeconds": 6,
            "HlsManifests": [{"Id": "index"}],
        },
        Tags={"sim2real": "true"},
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))

    assert created["CmafPackage"]["SegmentPrefix"] == channel_id, (
        f"expected default CmafPackage.SegmentPrefix to be the ChannelId {channel_id!r}, "
        f"got {created['CmafPackage'].get('SegmentPrefix')!r}"
    )

    described = mp.describe_origin_endpoint(Id=endpoint_id)
    assert described["CmafPackage"]["SegmentPrefix"] == channel_id, (
        f"expected DescribeOriginEndpoint to echo CmafPackage.SegmentPrefix {channel_id!r}, "
        f"got {described['CmafPackage'].get('SegmentPrefix')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

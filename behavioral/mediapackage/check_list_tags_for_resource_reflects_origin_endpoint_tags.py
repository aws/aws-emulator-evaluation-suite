"""list-tags-for-resource-reflects-origin-endpoint-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-reflects-origin-endpoint-tags"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags supplied at CreateOriginEndpoint time (a resource distinct from
    Channel) are readable via ListTagsForResource keyed by the OriginEndpoint's
    own Arn, and are independent of any tags on the parent Channel."""
    mp = ctx.client("mediapackage")
    channel_id = ctx.unique_name("sim2real-mp-chan-")
    channel = mp.create_channel(Id=channel_id, Tags={"scope": "channel"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=channel_id))
    channel_arn = channel["Arn"]

    endpoint_id = ctx.unique_name("sim2real-mp-ep-")
    created = mp.create_origin_endpoint(
        Id=endpoint_id,
        ChannelId=channel_id,
        Tags={"scope": "origin-endpoint"},
        HlsPackage={"SegmentDurationSeconds": 6},
    )
    ctx.on_cleanup(lambda: mp.delete_origin_endpoint(Id=endpoint_id))
    endpoint_arn = created["Arn"]

    endpoint_tags = mp.list_tags_for_resource(ResourceArn=endpoint_arn)["Tags"]
    assert endpoint_tags.get("scope") == "origin-endpoint", (
        "OriginEndpoint tags were not readable via its own Arn"
    )

    channel_tags = mp.list_tags_for_resource(ResourceArn=channel_arn)["Tags"]
    assert channel_tags.get("scope") == "channel", (
        "Channel tags must remain independent of the OriginEndpoint's own tags"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

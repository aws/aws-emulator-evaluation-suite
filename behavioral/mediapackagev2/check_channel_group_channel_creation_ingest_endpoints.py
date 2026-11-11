"""channel-group-channel-creation-ingest-endpoints."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "channel-group-channel-creation-ingest-endpoints"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel populates real ingest endpoints (URLs) that GetChannel then reflects."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    channel_name = ctx.unique_name("sim2real-mpv2-ch-")

    mp.create_channel_group(ChannelGroupName=group_name, Tags={"sim2real": CHECK})
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    created = mp.create_channel(
        ChannelGroupName=group_name, ChannelName=channel_name, Tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: mp.delete_channel(ChannelGroupName=group_name, ChannelName=channel_name))

    ingest_endpoints = created.get("IngestEndpoints", [])
    assert len(ingest_endpoints) >= 1, "CreateChannel returned no ingest endpoints"
    for ep in ingest_endpoints:
        assert ep.get("Url", "").startswith("https://"), f"ingest endpoint URL not https: {ep}"

    fetched = mp.get_channel(ChannelGroupName=group_name, ChannelName=channel_name)
    assert fetched["ChannelName"] == channel_name, (
        f"GetChannel ChannelName mismatch: expected {channel_name!r}, got {fetched['ChannelName']!r}"
    )
    assert fetched["ChannelGroupName"] == group_name, (
        f"GetChannel ChannelGroupName mismatch: expected {group_name!r}, got {fetched['ChannelGroupName']!r}"
    )
    fetched_ids = {e["Id"] for e in fetched.get("IngestEndpoints", [])}
    created_ids = {e["Id"] for e in ingest_endpoints}
    assert fetched_ids == created_ids, "GetChannel ingest endpoint IDs differ from CreateChannel response"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

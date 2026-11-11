"""update-channel-group-etag-changes-after-update."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-channel-group-etag-changes-after-update"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannelGroup persists the new Description and rotates the ETag used for optimistic concurrency."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")

    created = mp.create_channel_group(
        ChannelGroupName=group_name, Description="initial", Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    original_etag = created["ETag"]

    updated = mp.update_channel_group(ChannelGroupName=group_name, ETag=original_etag, Description="updated")
    assert updated["Description"] == "updated", f"expected Description 'updated', got {updated['Description']!r}"
    assert updated["ETag"] != original_etag, "ETag did not rotate after a successful update"

    fetched = mp.get_channel_group(ChannelGroupName=group_name)
    assert fetched["Description"] == "updated", f"expected persisted Description 'updated', got {fetched['Description']!r}"
    assert fetched["ETag"] == updated["ETag"], (
        f"expected GetChannelGroup ETag to match UpdateChannelGroup's response ETag {updated['ETag']!r}, "
        f"got {fetched['ETag']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

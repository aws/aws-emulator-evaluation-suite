"""update-channel-group-description-etag-rotates."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-channel-group-description-etag-rotates"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannelGroup with a new Description persists (visible on GetChannelGroup)
    and rotates the ETag."""
    mp = ctx.client("mediapackagev2")

    group_name = ctx.unique_name("sim2real-mpv2-cg-")
    created = mp.create_channel_group(
        ChannelGroupName=group_name,
        Description="original",
        Tags={"sim2real-check": CHECK},
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))
    old_etag = created["ETag"]
    assert created["Description"] == "original", (
        f"expected Description 'original' on create, got {created['Description']!r}"
    )

    updated = mp.update_channel_group(
        ChannelGroupName=group_name, Description="updated", ETag=old_etag
    )
    assert updated["Description"] == "updated", (
        f"expected Description 'updated' after UpdateChannelGroup, got {updated['Description']!r}"
    )
    new_etag = updated["ETag"]
    assert new_etag != old_etag, "ETag did not rotate after a successful update"

    got = mp.get_channel_group(ChannelGroupName=group_name)
    assert got["Description"] == "updated", (
        f"expected GetChannelGroup to reflect 'updated', got {got['Description']!r}"
    )
    assert got["ETag"] == new_etag, (
        f"expected GetChannelGroup ETag to match the rotated ETag {new_etag!r}, got {got['ETag']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

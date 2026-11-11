"""update-channel-persists-description."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-channel-persists-description"
GROUP = "state"
SERVICES = ["mediapackage"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannel's new Description is durably visible via DescribeChannel and
    ListChannels."""
    mp = ctx.client("mediapackage")

    cid = ctx.unique_name("sim2real-mp-desc-")
    mp.create_channel(Id=cid, Description="original-description", Tags={"purpose": "behavioral-check"})
    ctx.on_cleanup(lambda: mp.delete_channel(Id=cid))

    mp.update_channel(Id=cid, Description="updated-description")

    described = mp.describe_channel(Id=cid)
    assert described["Description"] == "updated-description", (
        f"expected DescribeChannel to reflect updated Description 'updated-description', "
        f"got {described['Description']!r}"
    )

    listed = mp.list_channels()["Channels"]
    match = next((c for c in listed if c["Id"] == cid), None)
    assert match is not None, "updated channel must still appear in ListChannels"
    assert match["Description"] == "updated-description", (
        f"expected ListChannels entry for {cid!r} to show Description 'updated-description', "
        f"got {match['Description']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

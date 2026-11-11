"""list-channels-filter-by-name-returns-subset."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-channels-filter-by-name-returns-subset"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """filterByName on ListChannels returns only the channel with that exact name."""
    ivs = ctx.client("ivs")
    target_name = ctx.unique_name("sim2real-ivs-filt-target-")
    other_name = ctx.unique_name("sim2real-ivs-filt-other-")

    target = ivs.create_channel(name=target_name, tags={"sim2real": "true"})["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=target["arn"]))
    other = ivs.create_channel(name=other_name, tags={"sim2real": "true"})["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=other["arn"]))

    filtered = ivs.list_channels(filterByName=target_name)["channels"]
    assert len(filtered) == 1, f"expected exactly one channel named {target_name!r}, got {filtered!r}"
    assert filtered[0]["arn"] == target["arn"], f"expected arn {target['arn']!r}, got {filtered[0]['arn']!r}"
    assert filtered[0]["name"] == target_name, f"expected name {target_name!r}, got {filtered[0]['name']!r}"

    filtered_other = ivs.list_channels(filterByName=other_name)["channels"]
    assert len(filtered_other) == 1, f"expected exactly one channel named {other_name!r}, got {filtered_other!r}"
    assert filtered_other[0]["arn"] == other["arn"], (
        f"expected arn {other['arn']!r}, got {filtered_other[0]['arn']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

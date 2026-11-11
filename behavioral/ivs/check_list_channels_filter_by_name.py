"""list-channels-filter-by-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-channels-filter-by-name"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChannels with filterByName returns only the channel matching that exact
    name, excluding other channels in the account."""
    ivs = ctx.client("ivs")
    name1 = ctx.unique_name("sim2real-ivs-filta-")
    name2 = ctx.unique_name("sim2real-ivs-filtb-")

    arn1 = ivs.create_channel(name=name1, tags={"purpose": "sim2real"})["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn1))
    arn2 = ivs.create_channel(name=name2, tags={"purpose": "sim2real"})["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn2))

    matched = ivs.list_channels(filterByName=name1)["channels"]
    assert len(matched) == 1, f"expected exactly 1 channel named {name1!r}, got {matched}"
    assert matched[0]["arn"] == arn1, f"expected arn {arn1!r}, got {matched[0]['arn']!r}"
    assert matched[0]["name"] == name1, f"expected name {name1!r}, got {matched[0]['name']!r}"

    matched2 = ivs.list_channels(filterByName=name2)["channels"]
    assert len(matched2) == 1, f"expected exactly 1 channel named {name2!r}, got {matched2}"
    assert matched2[0]["arn"] == arn2, f"expected arn {arn2!r}, got {matched2[0]['arn']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

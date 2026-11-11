"""create-channel-group-idempotent-retry-same-params-succeeds."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-channel-group-idempotent-retry-same-params-succeeds"
GROUP = "state"
SERVICES = ["mediapackagev2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retrying CreateChannelGroup with the same ClientToken AND the same parameters succeeds idempotently."""
    mp = ctx.client("mediapackagev2")
    group_name = ctx.unique_name("sim2real-mpv2-grp-")
    token = ctx.unique_name("sim2real-mpv2-tok-")

    first = mp.create_channel_group(
        ChannelGroupName=group_name, ClientToken=token, Description="same-desc", Tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: mp.delete_channel_group(ChannelGroupName=group_name))

    second = mp.create_channel_group(
        ChannelGroupName=group_name, ClientToken=token, Description="same-desc", Tags={"sim2real": CHECK}
    )

    assert first["Arn"] == second["Arn"], (
        f"idempotent replay changed Arn: {first['Arn']!r} != {second['Arn']!r}"
    )
    assert second["ChannelGroupName"] == group_name, (
        f"expected ChannelGroupName {group_name!r}, got {second['ChannelGroupName']!r}"
    )
    assert second["Description"] == "same-desc", (
        f"idempotent replay changed Description: {second['Description']!r}"
    )

    fetched = mp.get_channel_group(ChannelGroupName=group_name)
    assert fetched["Arn"] == first["Arn"], (
        f"independent read returned a different Arn: {fetched['Arn']!r} != {first['Arn']!r}"
    )
    assert fetched["Description"] == "same-desc", (
        f"independent read returned Description {fetched['Description']!r}, expected 'same-desc' "
        f"(no duplicate resource was silently created by the retry)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

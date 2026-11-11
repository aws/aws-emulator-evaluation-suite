"""update-channel-persists-change."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-channel-persists-change"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannel's new name/latencyMode values are durably reflected by a subsequent
    GetChannel."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    arn = ivs.create_channel(
        name=name, latencyMode="LOW", tags={"purpose": "sim2real"}
    )["channel"]["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    new_name = ctx.unique_name("sim2real-ivs-chan-upd-")
    ivs.update_channel(arn=arn, name=new_name, latencyMode="NORMAL")

    got = ivs.get_channel(arn=arn)["channel"]
    assert got["name"] == new_name, f"expected name {new_name!r}, got {got['name']!r}"
    assert got["latencyMode"] == "NORMAL", (
        f"expected latencyMode 'NORMAL', got {got['latencyMode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

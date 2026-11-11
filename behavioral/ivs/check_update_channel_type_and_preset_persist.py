"""update-channel-type-and-preset-persist."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-channel-type-and-preset-persist"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateChannel field changes (latencyMode, preset) persist and are visible on
    a subsequent GetChannel -- this is more than an echo of the request, it is a
    genuine read-after-write of server-held state."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    # ADVANCED_SD is one of the two channel types for which `preset` is selectable.
    created = ivs.create_channel(
        name=name, type="ADVANCED_SD", tags={"purpose": "sim2real"}
    )["channel"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=created["arn"]))

    # Documented default for ADVANCED_SD/ADVANCED_HD is HIGHER_BANDWIDTH_DELIVERY.
    assert created["preset"] == "HIGHER_BANDWIDTH_DELIVERY"
    assert created["latencyMode"] == "LOW"

    ivs.update_channel(
        arn=created["arn"],
        latencyMode="NORMAL",
        preset="CONSTRAINED_BANDWIDTH_DELIVERY",
    )

    updated = ivs.get_channel(arn=created["arn"])["channel"]
    assert updated["latencyMode"] == "NORMAL"
    assert updated["preset"] == "CONSTRAINED_BANDWIDTH_DELIVERY"
    # Unrelated fields are untouched by the partial update.
    assert updated["type"] == "ADVANCED_SD"
    assert updated["name"] == name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

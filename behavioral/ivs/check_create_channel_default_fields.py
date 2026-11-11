"""create-channel-default-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-channel-default-fields"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel applies documented defaults for latencyMode/type/authorized/insecureIngest
    when they are omitted, and CreateChannel also implicitly provisions a stream key."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    resp = ivs.create_channel(name=name, tags={"purpose": "sim2real"})
    channel = resp["channel"]
    arn = channel["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    assert channel["name"] == name, f"expected name {name!r}, got {channel['name']!r}"
    assert channel["latencyMode"] == "LOW", (
        f"expected default latencyMode LOW, got {channel['latencyMode']!r}"
    )
    assert channel["type"] == "STANDARD", (
        f"expected default type STANDARD, got {channel['type']!r}"
    )
    assert channel["authorized"] is False, (
        f"expected default authorized False, got {channel['authorized']!r}"
    )
    assert channel["insecureIngest"] is False, (
        f"expected default insecureIngest False, got {channel['insecureIngest']!r}"
    )
    assert "streamKey" in resp, "CreateChannel response is missing streamKey"
    assert resp["streamKey"]["channelArn"] == arn, (
        f"expected streamKey.channelArn {arn!r}, got {resp['streamKey']['channelArn']!r}"
    )

    got = ivs.get_channel(arn=arn)["channel"]
    assert got["name"] == name, f"GetChannel: expected name {name!r}, got {got['name']!r}"
    assert got["latencyMode"] == "LOW", (
        f"GetChannel: expected latencyMode LOW, got {got['latencyMode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""create-channel-reflects-configured-fields."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-channel-reflects-configured-fields"
GROUP = "control-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateChannel persists the requested configuration and GetChannel reads it back unchanged."""
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-chan-")
    created = ivs.create_channel(
        name=name,
        latencyMode="NORMAL",
        type="ADVANCED_SD",
        authorized=True,
        insecureIngest=False,
        tags={"purpose": "sim2real"},
    )
    channel = created["channel"]
    arn = channel["arn"]
    ctx.on_cleanup(lambda: ivs.delete_channel(arn=arn))

    # Response of CreateChannel itself must already reflect the configured fields.
    assert channel["name"] == name, f"name: expected {name!r}, got {channel['name']!r}"
    assert channel["latencyMode"] == "NORMAL", (
        f"latencyMode: expected NORMAL, got {channel['latencyMode']!r}"
    )
    assert channel["type"] == "ADVANCED_SD", f"type: expected ADVANCED_SD, got {channel['type']!r}"
    assert channel["authorized"] is True, f"authorized: expected True, got {channel['authorized']!r}"
    assert channel["insecureIngest"] is False, (
        f"insecureIngest: expected False, got {channel['insecureIngest']!r}"
    )
    assert channel["ingestEndpoint"], "ingestEndpoint: expected a non-empty value, got falsy"
    assert channel["playbackUrl"], "playbackUrl: expected a non-empty value, got falsy"

    fetched = ivs.get_channel(arn=arn)["channel"]
    assert fetched["name"] == name, f"GetChannel name: expected {name!r}, got {fetched['name']!r}"
    assert fetched["latencyMode"] == "NORMAL", (
        f"GetChannel latencyMode: expected NORMAL, got {fetched['latencyMode']!r}"
    )
    assert fetched["type"] == "ADVANCED_SD", (
        f"GetChannel type: expected ADVANCED_SD, got {fetched['type']!r}"
    )
    assert fetched["authorized"] is True, (
        f"GetChannel authorized: expected True, got {fetched['authorized']!r}"
    )
    assert fetched["insecureIngest"] is False, (
        f"GetChannel insecureIngest: expected False, got {fetched['insecureIngest']!r}"
    )
    assert fetched["arn"] == arn, f"GetChannel arn: expected {arn!r}, got {fetched['arn']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

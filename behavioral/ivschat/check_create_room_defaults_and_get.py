"""create-room-defaults-and-get."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-room-defaults-and-get"
GROUP = "state"
SERVICES = ["ivschat"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRoom without rate/length params applies documented defaults (10 msg/s, 500 chars),
    and GetRoom reflects them exactly."""
    ivschat = ctx.client("ivschat")
    name = ctx.unique_name("sim2real-ivschat-room")
    created = ivschat.create_room(name=name, tags={"sim2real": "true"})
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=arn))

    assert created["maximumMessageRatePerSecond"] == 10, (
        f"expected documented default rate 10, got {created['maximumMessageRatePerSecond']!r}"
    )
    assert created["maximumMessageLength"] == 500, (
        f"expected documented default length 500, got {created['maximumMessageLength']!r}"
    )

    got = ivschat.get_room(identifier=arn)
    assert got["arn"] == arn, f"expected arn {arn!r}, got {got['arn']!r}"
    assert got["name"] == name, f"expected name {name!r}, got {got['name']!r}"
    assert got["maximumMessageRatePerSecond"] == 10, (
        f"GetRoom expected default rate 10, got {got['maximumMessageRatePerSecond']!r}"
    )
    assert got["maximumMessageLength"] == 500, (
        f"GetRoom expected default length 500, got {got['maximumMessageLength']!r}"
    )
    assert got.get("loggingConfigurationIdentifiers", []) == [], (
        "expected no logging configurations attached by default, got "
        f"{got.get('loggingConfigurationIdentifiers')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

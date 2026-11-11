"""update-room-persists-changes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-room-persists-changes"
GROUP = "state"
SERVICES = ["ivschat"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateRoom mutates maximumMessageLength/maximumMessageRatePerSecond/name and the new
    values are durably reflected by a subsequent GetRoom (not just echoed in the response)."""
    ivschat = ctx.client("ivschat")
    name = ctx.unique_name("sim2real-ivschat-room")
    created = ivschat.create_room(name=name, tags={"sim2real:managed": "true"})
    arn = created["arn"]
    ctx.on_cleanup(lambda: ivschat.delete_room(identifier=arn))
    original_update_time = created["updateTime"]

    new_name = ctx.unique_name("sim2real-ivschat-renamed")
    updated = ivschat.update_room(
        identifier=arn,
        name=new_name,
        maximumMessageLength=250,
        maximumMessageRatePerSecond=42,
    )
    assert updated["name"] == new_name, f"expected name={new_name!r}, got {updated['name']!r}"
    assert updated["maximumMessageLength"] == 250, (
        f"expected maximumMessageLength=250, got {updated['maximumMessageLength']!r}"
    )
    assert updated["maximumMessageRatePerSecond"] == 42, (
        f"expected maximumMessageRatePerSecond=42, got {updated['maximumMessageRatePerSecond']!r}"
    )

    got = ivschat.get_room(identifier=arn)
    assert got["name"] == new_name, (
        f"GetRoom name not persisted: expected {new_name!r}, got {got['name']!r}"
    )
    assert got["maximumMessageLength"] == 250, (
        f"GetRoom maximumMessageLength not persisted: expected 250, got {got['maximumMessageLength']!r}"
    )
    assert got["maximumMessageRatePerSecond"] == 42, (
        f"GetRoom maximumMessageRatePerSecond not persisted: expected 42, got {got['maximumMessageRatePerSecond']!r}"
    )
    assert got["updateTime"] > original_update_time, (
        f"updateTime did not advance: original={original_update_time!r} got={got['updateTime']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

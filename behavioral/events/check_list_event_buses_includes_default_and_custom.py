"""list-event-buses-includes-default-and-custom."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-event-buses-includes-default-and-custom"
GROUP = 'event-bus'
SERVICES = ['events']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListEventBuses reflects both the always-present default bus and a
    newly created custom bus, and NamePrefix filtering is honored."""
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-evb-bus-")
    ev.create_event_bus(Name=name)
    ctx.on_cleanup(lambda: ev.delete_event_bus(Name=name))

    filtered = ev.list_event_buses(NamePrefix=name)["EventBuses"]
    assert {b["Name"] for b in filtered} == {name}, f"NamePrefix filter broken: {filtered}"

    default_only = ev.list_event_buses(NamePrefix="default")["EventBuses"]
    assert "default" in {b["Name"] for b in default_only}, (
        f"default bus must always be listed, got {default_only}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

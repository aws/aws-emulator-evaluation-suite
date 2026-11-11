"""update-discoverer-preserves-state."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-discoverer-preserves-state"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateDiscoverer changes Description but never mutates the discoverer's STARTED/STOPPED State."""
    events = ctx.client("events")
    schemas = ctx.client("schemas")

    bus_name = ctx.unique_name("sim2real-schemas-bus-")
    bus_arn = events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real", "Value": "true"}])[
        "EventBusArn"
    ]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    created = schemas.create_discoverer(
        SourceArn=bus_arn, Description="initial", Tags={"sim2real": "true"}
    )
    discoverer_id = created["DiscovererId"]
    ctx.on_cleanup(lambda: schemas.delete_discoverer(DiscovererId=discoverer_id))
    assert created["State"] == "STARTED", f"expected STARTED on create, got {created['State']!r}"

    stopped = schemas.stop_discoverer(DiscovererId=discoverer_id)
    assert stopped["State"] == "STOPPED", f"expected STOPPED from StopDiscoverer, got {stopped['State']!r}"

    updated = schemas.update_discoverer(DiscovererId=discoverer_id, Description="renamed")
    assert updated["Description"] == "renamed", (
        f"expected Description 'renamed' from UpdateDiscoverer, got {updated['Description']!r}"
    )
    assert updated["State"] == "STOPPED", (
        f"UpdateDiscoverer must not mutate State; expected STOPPED, got {updated['State']!r}"
    )

    described = schemas.describe_discoverer(DiscovererId=discoverer_id)
    assert described["Description"] == "renamed", (
        f"expected persisted Description 'renamed', got {described['Description']!r}"
    )
    assert described["State"] == "STOPPED", (
        f"expected persisted State STOPPED after update, got {described['State']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

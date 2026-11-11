"""discoverer-lifecycle-start-stop-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "discoverer-lifecycle-start-stop-transitions"
GROUP = "state"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Discoverer starts STARTED, transitions to STOPPED on StopDiscoverer, then back to STARTED."""
    events = ctx.client("events")
    schemas = ctx.client("schemas")

    bus_name = ctx.unique_name("sim2real-schemas-bus-")
    bus_arn = events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    created = schemas.create_discoverer(
        SourceArn=bus_arn, Description="behavioral lifecycle test", Tags={"sim2real": CHECK}
    )
    discoverer_id = created["DiscovererId"]
    ctx.on_cleanup(lambda: schemas.delete_discoverer(DiscovererId=discoverer_id))
    assert created["State"] == "STARTED", f"expected STARTED on create, got {created['State']!r}"

    stopped = schemas.stop_discoverer(DiscovererId=discoverer_id)
    assert stopped["State"] == "STOPPED", f"expected STOPPED from StopDiscoverer, got {stopped['State']!r}"
    after_stop = _poll_until(
        lambda: schemas.describe_discoverer(DiscovererId=discoverer_id)["State"],
        lambda state: state == "STOPPED",
        timeout_s=30.0,
    )
    assert after_stop == "STOPPED", f"expected DescribeDiscoverer to settle at STOPPED, got {after_stop!r}"

    started = schemas.start_discoverer(DiscovererId=discoverer_id)
    assert started["State"] == "STARTED", f"expected STARTED from StartDiscoverer, got {started['State']!r}"
    after_start = _poll_until(
        lambda: schemas.describe_discoverer(DiscovererId=discoverer_id)["State"],
        lambda state: state == "STARTED",
        timeout_s=30.0,
    )
    assert after_start == "STARTED", f"expected DescribeDiscoverer to settle at STARTED, got {after_start!r}"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=1.5):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

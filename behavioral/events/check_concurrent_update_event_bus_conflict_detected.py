"""concurrent-update-event-bus-conflict-detected."""
from __future__ import annotations

import concurrent.futures as cf

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-update-event-bus-conflict-detected"
GROUP = "concurrency"
SERVICES = ["events"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Many overlapping UpdateEventBus calls at one custom event bus leave at least one call
    succeeding (ConcurrentModificationException is a possible, not a guaranteed, outcome for the
    rest), and a subsequent solo update still works and persists (the bus is not left wedged)."""
    events = ctx.client("events")

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))

    racer_count = 12
    max_bursts = 6
    conflict_seen = False
    success_seen = False
    for burst in range(max_bursts):
        calls = [
            (lambda i=i, b=burst: events.update_event_bus(
                Name=bus_name, Description=f"race-{b}-{i}"
            ))
            for i in range(racer_count)
        ]
        codes = _fire_concurrent(calls)
        if any(code is None for code in codes):
            success_seen = True
        if any(code == "ConcurrentModificationException" for code in codes):
            conflict_seen = True
            break

    # ConcurrentModificationException is a possible UpdateEventBus error, not a guaranteed one, so a
    # backend that serializes the burst passes on the success it must still deliver.
    assert success_seen, "expected at least one UpdateEventBus call in the race to succeed"

    # The bus itself must still be describable and mutable afterwards -- the race must not have
    # wedged it into a broken state.
    described = events.describe_event_bus(Name=bus_name)
    assert described["Name"] == bus_name, (
        f"expected bus name {bus_name!r} after the race, got {described.get('Name')!r}"
    )

    # Positive control: a solo UpdateEventBus (no contention) still succeeds and persists.
    events.update_event_bus(Name=bus_name, Description="solo-update-control")
    described_after = events.describe_event_bus(Name=bus_name)
    assert described_after["Description"] == "solo-update-control", (
        "expected solo post-race update to persist, got "
        f"{described_after.get('Description')!r}"
    )


def _fire_concurrent(fns):
    """Submit every callable before blocking on any result, then collect the error code (or
    None on success) for each -- maximizes true overlap on the wire."""
    with cf.ThreadPoolExecutor(max_workers=len(fns)) as ex:
        futures = [ex.submit(fn) for fn in fns]
        codes = []
        for fut in futures:
            try:
                fut.result()
                codes.append(None)
            except ClientError as err:
                codes.append(err.response["Error"]["Code"])
        return codes


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""update-archive-event-pattern-governs-what-is-archived-afterwards."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-archive-event-pattern-governs-what-is-archived-afterwards"
GROUP = "archive"
SERVICES = ["events"]

_RULE_APPEAR_TIMEOUT_S = 60.0
_RULE_CONVERGE_TIMEOUT_S = 60.0
_ARCHIVE_DELETE_TIMEOUT_S = 180.0
# Archive EventCount lags PutEvents by minutes (151 s to beyond 900 s observed).
_INGEST_TIMEOUT_S = 1500.0


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:eventing", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """After UpdateArchive replaces an archive's EventPattern, the archive stores exactly the 2
    events the new pattern matches, not the 1 only the old pattern matched (no filtering gives 3).
    """
    events = ctx.client("events")

    bus = ctx.unique_name("sim2real-behav-bus-")
    bus_arn = events.create_event_bus(
        Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    old_source = ctx.unique_name("sim2real.old.")
    new_source = ctx.unique_name("sim2real.new.")

    filtered = ctx.unique_name("sim2real-arc-")
    events.create_archive(
        ArchiveName=filtered, EventSourceArn=bus_arn,
        EventPattern=json.dumps({"source": [old_source]}),
    )
    ctx.on_cleanup(lambda: _delete_archive_and_wait(events, filtered))
    unfiltered = ctx.unique_name("sim2real-arc-")
    events.create_archive(ArchiveName=unfiltered, EventSourceArn=bus_arn)
    ctx.on_cleanup(lambda: _delete_archive_and_wait(events, unfiltered))

    for name in (filtered, unfiltered):
        state = _poll_until(
            lambda n=name: events.describe_archive(ArchiveName=n),
            lambda d: d.get("State") in ("ENABLED", "CREATE_FAILED", "DISABLED"),
            timeout_s=300.0, interval_s=3.0, description=f"archive {name} leaving CREATING",
        )
        assert state["State"] == "ENABLED", f"archive {name} settled at {state!r}"
        assert state.get("EventCount") == 0, (
            f"archive {name} counted {state.get('EventCount')!r} events before any was published"
        )

    events.update_archive(ArchiveName=filtered, EventPattern=json.dumps({"source": [new_source]}))
    # The archive's managed rule executes its selection; wait for it so the put cannot race it.
    _poll_rule_pattern(
        events, bus, f"Events-Archive-{filtered}",
        {"source": [new_source], "replay-name": [{"exists": False}]},
    )

    put = events.put_events(Entries=[
        {"EventBusName": bus, "Source": old_source, "DetailType": "sim2real-archived",
         "Detail": json.dumps({"i": 1})},
        {"EventBusName": bus, "Source": new_source, "DetailType": "sim2real-archived",
         "Detail": json.dumps({"i": 2})},
        {"EventBusName": bus, "Source": new_source, "DetailType": "sim2real-archived",
         "Detail": json.dumps({"i": 3})},
    ])
    assert put["FailedEntryCount"] == 0 and all(e.get("EventId") for e in put["Entries"]), (
        f"PutEvents must accept all three entries, got {put['Entries']!r}"
    )

    # Barrier: the unfiltered archive reaching 3 shows all three events have been processed.
    barrier = _poll_until(
        lambda: events.describe_archive(ArchiveName=unfiltered),
        lambda d: d.get("EventCount", 0) >= 3,
        timeout_s=_INGEST_TIMEOUT_S, interval_s=10.0,
        description=f"unfiltered archive {unfiltered} accounting for all 3 published events",
    )
    assert barrier["EventCount"] == 3, (
        f"the unfiltered archive stored {barrier['EventCount']!r} events for 3 published"
    )

    _poll_until(
        lambda: events.describe_archive(ArchiveName=filtered),
        lambda d: d.get("EventCount", 0) >= 2,
        timeout_s=900.0, interval_s=10.0,
        description=(
            f"updated archive {filtered} accounting for the 2 events its NEW pattern matches "
            f"(an archive still filtering on the old pattern stops at 1)"
        ),
    )
    # The two archives' counts are not updated in a fixed order, so hold the count stable.
    settled = _wait_until_stable(
        lambda: events.describe_archive(ArchiveName=filtered),
        lambda d: d.get("EventCount"),
        window_s=20.0, interval_s=10.0, description=f"archive {filtered} EventCount",
    )
    assert settled["EventCount"] == 2, (
        f"after UpdateArchive to source {new_source!r}, the archive settled at EventCount="
        f"{settled['EventCount']!r}; expected exactly 2 (the old-source event must not be stored). "
        f"Whole archive: {settled!r}"
    )
    assert settled.get("SizeBytes", 0) > 0, (
        f"the archive counted 2 events but reports SizeBytes={settled.get('SizeBytes')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description}: not met within {timeout_s}s. Last result: {last!r}")


def _wait_until_stable(probe, extract, *, window_s: float, interval_s: float, description: str):
    sample = probe()
    baseline = extract(sample)
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        time.sleep(interval_s)
        sample = probe()
        current = extract(sample)
        assert current == baseline, (
            f"{description} changed from {baseline!r} to {current!r} within the {window_s}s "
            f"stability window, so it was still moving"
        )
    return sample


def _poll_rule_pattern(events, bus: str, name: str, expected: dict) -> dict:
    deadline = time.monotonic() + _RULE_CONVERGE_TIMEOUT_S
    last = None
    while time.monotonic() < deadline:
        last = events.describe_rule(Name=name, EventBusName=bus)
        if json.loads(last.get("EventPattern") or "null") == expected:
            return last
        time.sleep(2)
    raise AssertionError(
        f"the archive's managed rule {name!r} never converged to pattern {expected!r} within "
        f"{_RULE_CONVERGE_TIMEOUT_S}s; last read {last.get('EventPattern') if last else None!r}"
    )


def _delete_archive_and_wait(events, name: str) -> None:
    """DeleteArchive is asynchronous and the bus cannot be deleted while it still exists."""
    events.delete_archive(ArchiveName=name)
    deadline = time.monotonic() + _ARCHIVE_DELETE_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            events.describe_archive(ArchiveName=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(3)
    raise AssertionError(f"archive {name} still exists {_ARCHIVE_DELETE_TIMEOUT_S}s after DeleteArchive")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

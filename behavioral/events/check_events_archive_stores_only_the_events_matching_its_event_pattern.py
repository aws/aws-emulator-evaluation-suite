"""events-archive-stores-only-the-events-matching-its-event-pattern."""

from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "events-archive-stores-only-the-events-matching-its-event-pattern"

GROUP = "archive"

SERVICES = ["events"]


@tags("axis:happy-path", "concern:data-plane", "concern:eventing", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """An archive with an EventPattern stores only matching events: of three events put once, its
    EventCount settles at exactly 2 while an unfiltered archive on the same bus reaches 3.
    """
    events = ctx.client("events")
    matching_source = _xname(ctx, "src-match").replace("-", ".")
    other_source = _xname(ctx, "src-other").replace("-", ".")

    bus = _xname(ctx, "bus")
    bus_arn = events.create_event_bus(Name=bus, Tags=_xsvc_tags_kv())["EventBusArn"]
    ctx.on_cleanup(lambda: ctx.client("events").delete_event_bus(Name=bus))

    filtered = _create_archive(ctx, bus_arn, event_pattern={"source": [matching_source]})
    unfiltered = _create_archive(ctx, bus_arn, event_pattern=None)

    for name in (filtered, unfiltered):
        state = _poll_until(
            lambda n=name: events.describe_archive(ArchiveName=n),
            lambda d: d.get("State") in ("ENABLED", "CREATE_FAILED", "DISABLED"),
            timeout_s=300.0,
            interval_s=3.0,
            description=f"archive {name} left CREATING",
        )
        assert state["State"] == "ENABLED", (
            f"archive {name} settled at State={state['State']!r}, expected 'ENABLED'; the whole "
            f"archive was {state!r}"
        )
        assert state.get("EventCount") == 0, (
            f"archive {name} reported EventCount={state.get('EventCount')!r} before a single event "
            f"was published, so any count measured later is not attributable to this check"
        )

    # One PutEvents, so both archives see all three events at the same instant.
    resp = events.put_events(
        Entries=[
            {
                "Source": matching_source,
                "DetailType": "Archived",
                "Detail": json.dumps({"i": 1}),
                "EventBusName": bus,
            },
            {
                "Source": matching_source,
                "DetailType": "Archived",
                "Detail": json.dumps({"i": 2}),
                "EventBusName": bus,
            },
            {
                "Source": other_source,
                "DetailType": "Archived",
                "Detail": json.dumps({"i": 3}),
                "EventBusName": bus,
            },
        ]
    )
    assert resp.get("FailedEntryCount") == 0, (
        f"PutEvents did not accept all three entries, so the non-matching event's absence from the "
        f"filtered archive would be a rejected put rather than filtering: {resp!r}"
    )
    entries = resp.get("Entries", [])
    assert len(entries) == 3 and all(e.get("EventId") for e in entries), (
        f"PutEvents returned no EventId for every entry, so all three were not really published: "
        f"{entries!r}"
    )

    # The barrier: wait for the UNFILTERED archive to account for all three events. EventCount
    # lags PutEvents by minutes on real AWS, hence the long bound.
    all_desc = _poll_until(
        lambda: events.describe_archive(ArchiveName=unfiltered),
        lambda d: d.get("EventCount", 0) >= 3,
        timeout_s=900.0,
        interval_s=5.0,
        description=(
            f"unfiltered archive {unfiltered} accounted for all 3 published events (real AWS took "
            f"353 s when this check was written)"
        ),
    )
    assert all_desc["EventCount"] == 3, (
        f"the unfiltered archive on the same bus stored {all_desc['EventCount']!r} events for 3 "
        f"published, so the barrier itself is wrong: {all_desc!r}"
    )
    assert all_desc.get("SizeBytes", 0) > 0, (
        f"the unfiltered archive counted 3 events but reports SizeBytes="
        f"{all_desc.get('SizeBytes')!r}: the count is bookkeeping, nothing was stored"
    )

    # The pipeline has demonstrably finished with all three events (the unfiltered archive proves
    # it), but that does NOT mean the filtered archive's own count has caught up yet -- the two
    # archives' latencies are independent. Poll the filtered archive to ITS OWN target first.
    _poll_until(
        lambda: events.describe_archive(ArchiveName=filtered),
        lambda d: d.get("EventCount", 0) >= 2,
        timeout_s=600.0,
        interval_s=5.0,
        description=(
            f"filtered archive {filtered} accounted for both of the matching published events"
        ),
    )

    # Now that it has reached 2, sample it across a bounded 20 s window and require every sample
    # to agree -- a count still climbing past 2 would make the equality below a race rather than a
    # measurement.
    second = _wait_until_stable(
        lambda: events.describe_archive(ArchiveName=filtered),
        lambda d: d.get("EventCount"),
        window_s=20.0,
        interval_s=10.0,
        description=f"archive {filtered} EventCount",
    )
    assert second["EventCount"] == 2, (
        f"the archive with EventPattern {{'source': [{matching_source!r}]}} settled at EventCount="
        f"{second['EventCount']!r}, expected exactly 2. Two of the three published events matched "
        f"that pattern and one did not; an archive that stores everything lands on 3, and one that "
        f"stores nothing lands on 0. The whole archive was {second!r}"
    )
    assert second.get("SizeBytes", 0) > 0, (
        f"the filtered archive counted 2 events but reports SizeBytes="
        f"{second.get('SizeBytes')!r}: the count is bookkeeping, nothing was stored"
    )
    assert second.get("EventPattern") and matching_source in second["EventPattern"], (
        f"DescribeArchive no longer reports the pattern the filtering was attributed to: "
        f"EventPattern={second.get('EventPattern')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>.

    ArchiveName is capped at 48 characters by real AWS, so archive kinds stay short."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_archive(ctx, bus_arn: str, *, event_pattern: dict | None) -> str:
    """Create an archive on `bus_arn` and register a teardown that WAITS for it to be gone.

    DeleteArchive is asynchronous and the bus cannot be deleted while an archive references it."""
    events = ctx.client("events")
    name = _xname(ctx, "arc")
    kwargs: dict[str, Any] = {"ArchiveName": name, "EventSourceArn": bus_arn}
    if event_pattern is not None:
        kwargs["EventPattern"] = json.dumps(event_pattern)
    events.create_archive(**kwargs)
    ctx.on_cleanup(lambda: _delete_archive_and_wait(ctx, name))
    return name


def _delete_archive_and_wait(ctx, name: str, *, timeout_s: float = 180.0) -> None:
    events = ctx.client("events")
    try:
        events.delete_archive(ArchiveName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise RuntimeError(f"could not delete archive {name}: {exc}") from exc
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            events.describe_archive(ArchiveName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
        time.sleep(3)
    raise RuntimeError(f"archive {name} still present {timeout_s}s after DeleteArchive; its event bus "
                       f"may fail to delete")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _wait_until_stable(probe, extract, *, window_s: float, interval_s: float, description: str):
    """Sample probe() every interval_s across window_s; raise the moment extract() disagrees with
    the first sample. Returns the final (fully agreeing) sample -- never a possibly-stale single
    read taken once and trusted."""
    sample = probe()
    baseline = extract(sample)
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        time.sleep(interval_s)
        sample = probe()
        current = extract(sample)
        assert current == baseline, (
            f"{description} changed from {baseline!r} to {current!r} within the {window_s}s "
            f"stability window, so it was still moving and no exact value is measurable here"
        )
    return sample


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

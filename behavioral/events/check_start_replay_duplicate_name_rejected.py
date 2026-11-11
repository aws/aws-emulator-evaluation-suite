"""start-replay-duplicate-name-rejected."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-replay-duplicate-name-rejected"
GROUP = "e2e"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartReplay with a ReplayName already in use fails with ResourceAlreadyExistsException and its
    exact message, leaves the original replay unchanged, and a fresh name on the same archive works."""
    events = ctx.client("events")

    bus_name = ctx.unique_name("sim2real-eb-bus-")
    archive_name = ctx.unique_name("sim2real-eb-arc-")
    replay_name = ctx.unique_name("sim2real-eb-replay-")
    replay_name_2 = ctx.unique_name("sim2real-eb-replay2-")
    source_name = ctx.unique_name("sim2real.dup.src.").replace("-", ".")

    bus_arn = events.create_event_bus(
        Name=bus_name, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )["EventBusArn"]
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))

    archive_arn = events.create_archive(
        ArchiveName=archive_name,
        EventSourceArn=bus_arn,
        EventPattern=json.dumps({"source": [source_name]}),
    )["ArchiveArn"]
    ctx.on_cleanup(lambda: events.delete_archive(ArchiveName=archive_name))

    _poll_until(
        lambda: events.describe_archive(ArchiveName=archive_name)["State"],
        lambda state: state == "ENABLED",
        timeout_s=60,
        interval_s=3,
    )

    now = datetime.now(timezone.utc)
    original_start = now - timedelta(minutes=10)
    original_end = now + timedelta(minutes=10)

    first = events.start_replay(
        ReplayName=replay_name,
        EventSourceArn=archive_arn,
        EventStartTime=original_start,
        EventEndTime=original_end,
        Destination={"Arn": bus_arn},
    )
    assert first["State"] in ("STARTING", "RUNNING", "COMPLETED"), (
        f"positive control: expected StartReplay to acknowledge with a valid initial state, got {first!r}"
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(events, replay_name))

    _poll_until(
        lambda: events.describe_replay(ReplayName=replay_name)["State"],
        lambda state: state in ("STARTING", "RUNNING", "COMPLETED"),
        timeout_s=30,
        interval_s=2,
    )

    # Reuse the name with a different time window.
    conflicting_end = now + timedelta(minutes=20)
    refusal = _error_of(
        lambda: events.start_replay(
            ReplayName=replay_name,
            EventSourceArn=archive_arn,
            EventStartTime=original_start,
            EventEndTime=conflicting_end,
            Destination={"Arn": bus_arn},
        )
    )
    assert refusal == ("ResourceAlreadyExistsException", f"Replay {replay_name} already exists."), (
        f"expected the duplicate-name StartReplay to be rejected with ResourceAlreadyExistsException, got {refusal!r}"
    )

    # EventEndTime is the one field the conflicting call tried to change, so it is the
    # assertion that discriminates.
    described = events.describe_replay(ReplayName=replay_name)
    assert described["EventSourceArn"] == archive_arn, (
        f"expected the original replay's EventSourceArn to survive the rejected call unchanged, got {described!r}"
    )
    assert described["Destination"]["Arn"] == bus_arn, (
        f"expected the original replay's Destination to survive the rejected call unchanged, got {described!r}"
    )
    end_drift_s = abs((described["EventEndTime"] - original_end).total_seconds())
    assert end_drift_s < 2, (
        f"expected EventEndTime to remain {original_end!r} (the rejected call asked for {conflicting_end!r} instead), "
        f"got {described['EventEndTime']!r}"
    )

    # A fresh name succeeds, so the rejection is specific to the name collision.
    second = events.start_replay(
        ReplayName=replay_name_2,
        EventSourceArn=archive_arn,
        EventStartTime=original_start,
        EventEndTime=original_end,
        Destination={"Arn": bus_arn},
    )
    assert second["State"] in ("STARTING", "RUNNING", "COMPLETED"), (
        f"expected StartReplay with a fresh name to acknowledge with a valid initial state, got {second!r}"
    )
    ctx.on_cleanup(lambda: _best_effort_cancel(events, replay_name_2))

    described_2 = events.describe_replay(ReplayName=replay_name_2)
    assert described_2["State"] in ("STARTING", "RUNNING", "COMPLETED"), (
        f"expected an independent DescribeReplay read of the fresh-name replay to show it running, got {described_2!r}"
    )


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met within {timeout_s}s, last value={last!r}")


def _error_of(fn: Callable[[], Any]) -> tuple[str, str]:
    """Return fn()'s botocore (code, message); raise if the call unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return (exc.response["Error"]["Code"], exc.response["Error"]["Message"])
    raise AssertionError(
        f"expected the duplicate-name StartReplay to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _best_effort_cancel(events_client, replay_name: str) -> None:
    try:
        state = events_client.describe_replay(ReplayName=replay_name)["State"]
        if state in ("STARTING", "RUNNING"):
            events_client.cancel_replay(ReplayName=replay_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

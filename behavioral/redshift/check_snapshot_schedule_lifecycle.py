"""snapshot-schedule-lifecycle."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


_THROTTLE = (
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "SlowDown",
)


def _code_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    return f"EXC:{type(exc).__name__}"


def _message_of(exc):
    if isinstance(exc, ClientError):
        return exc.response["Error"].get("Message", "")
    return str(exc)


def _retrying(fn, attempts=6, delay_s=5.0):
    """Call *fn*, retrying only on API throttling (a rate limit is infrastructure
    noise under parallel runs, not a behavioral observation)."""
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if _code_of(exc) not in _THROTTLE:
                raise
            last = exc
            time.sleep(delay_s * (attempt + 1))
    raise last


def _err(fn):
    """Call *fn*; return (AWS error code, message), or ("OK", "") if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc), _message_of(exc)
    return "OK", ""


def _probe_codes(cases):
    """{label: callable} -> {label: (error-code-or-"OK", message)}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}

CHECK = "snapshot-schedule-lifecycle"
GROUP = 'scheduling'
SERVICES = ['redshift']


def _delete_unless_gone(delete, gone_code):
    """Teardown delete; an already-deleted resource answers ``gone_code`` (documented not-found)."""
    try:
        delete()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != gone_code:
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Snapshot schedules: create stores the definition, modify REPLACES it, delete removes it and a
    second delete reports not-found."""
    rs = ctx.client("redshift")
    schedule_id = ctx.unique_name("sim2real-behav-rs-sched-")
    ctx.on_cleanup(lambda: _delete_unless_gone(
        lambda: rs.delete_snapshot_schedule(ScheduleIdentifier=schedule_id), "SnapshotScheduleNotFound"))
    created = rs.create_snapshot_schedule(
        ScheduleIdentifier=schedule_id,
        ScheduleDescription="behavioral fidelity snapshot schedule",
        ScheduleDefinitions=["rate(12 hours)"],
        Tags=[{"Key": "sim2real-behavioral", "Value": "true"}],
    )
    assert created["ScheduleIdentifier"] == schedule_id
    assert created["ScheduleDefinitions"] == ["rate(12 hours)"]
    assert created.get("AssociatedClusterCount", 0) == 0

    described = rs.describe_snapshot_schedules(ScheduleIdentifier=schedule_id)["SnapshotSchedules"]
    assert len(described) == 1, described
    assert described[0]["ScheduleDefinitions"] == ["rate(12 hours)"]
    assert described[0]["ScheduleDescription"] == "behavioral fidelity snapshot schedule"
    assert described[0].get("AssociatedClusters", []) == [], described[0]

    modified = rs.modify_snapshot_schedule(
        ScheduleIdentifier=schedule_id, ScheduleDefinitions=["rate(24 hours)"]
    )
    assert modified["ScheduleDefinitions"] == ["rate(24 hours)"], (
        "modify must REPLACE the definitions, not append"
    )

    rs.delete_snapshot_schedule(ScheduleIdentifier=schedule_id)
    code, message = _err(lambda: rs.delete_snapshot_schedule(ScheduleIdentifier=schedule_id))
    assert code == "SnapshotScheduleNotFound", f"expected SnapshotScheduleNotFound, got {code}"
    expected = f"Schedule not found for schedule identifier {schedule_id}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_there = rs.describe_snapshot_schedules(ScheduleIdentifier=schedule_id)["SnapshotSchedules"]
    assert still_there == [], f"a deleted schedule must not be resurrected in describe, got {still_there}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

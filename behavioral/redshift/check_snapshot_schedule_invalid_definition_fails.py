"""snapshot-schedule-invalid-definition-fails."""

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
    """Call *fn*; return the AWS error code, or "OK" if it succeeded."""
    try:
        _retrying(fn)
    except Exception as exc:  # noqa: BLE001 - behavioral probe of error semantics
        return _code_of(exc)
    return "OK"


def _error(fn):
    """Call *fn* and return the (code, message) of the AWS error it raises; a success fails."""
    try:
        _retrying(fn)
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("the call succeeded where AWS rejects it")


def _probe_codes(cases):
    """{label: callable} -> {label: error-code-or-"OK"}; never raises."""
    return {label: _err(fn) for label, fn in cases.items()}


def _delete_absent_ok(delete, gone_code):
    """Teardown: the snapshot schedule delete is synchronous; one that was never created answers *gone_code*."""
    try:
        delete()
    except ClientError as exc:
        if _code_of(exc) != gone_code:
            raise


CHECK = "snapshot-schedule-invalid-definition-fails"
GROUP = 'overly-permissive'
SERVICES = ['redshift']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateSnapshotSchedule rejects rate(5 minutes), finer than the 1-hour minimum, with
    InvalidSchedule and its exact message and creates nothing, while rate(1 hour) succeeds."""
    rs = ctx.client("redshift")

    good_id = ctx.unique_name("sim2real-behav-rs-schedgood-")
    ctx.on_cleanup(lambda: _delete_absent_ok(
        lambda: rs.delete_snapshot_schedule(ScheduleIdentifier=good_id), "SnapshotScheduleNotFound"
    ))
    created = rs.create_snapshot_schedule(
        ScheduleIdentifier=good_id,
        ScheduleDescription="behavioral fidelity positive control",
        ScheduleDefinitions=["rate(1 hour)"],
    )
    assert created["ScheduleDefinitions"] == ["rate(1 hour)"], (
        f"positive control at the 1-hour minimum did not succeed: {created!r}"
    )

    schedule_id = ctx.unique_name("sim2real-behav-rs-schedbad-")
    code, message = _error(lambda: rs.create_snapshot_schedule(
        ScheduleIdentifier=schedule_id,
        ScheduleDescription="behavioral fidelity invalid schedule",
        ScheduleDefinitions=["rate(5 minutes)"],
    ))
    assert code == "InvalidSchedule", f"expected InvalidSchedule, got {code}"
    assert message == "Schedule interval rate(5 minutes) is less than minimum interval of 60 minutes", message

    lookup = _err(lambda: rs.describe_snapshot_schedules(ScheduleIdentifier=schedule_id))
    assert lookup == "OK", f"describe of an unknown schedule filters rather than faults, got {lookup}"
    assert rs.describe_snapshot_schedules(ScheduleIdentifier=schedule_id)["SnapshotSchedules"] == [], (
        "the rejected schedule must not exist"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

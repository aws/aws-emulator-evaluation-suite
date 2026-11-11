"""maintenance-window-next-execution-time-recomputed."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-next-execution-time-recomputed"
GROUP = 'state-machine'
SERVICES = ['ssm']

_MONDAY_0400 = "cron(0 4 ? * MON *)"
_WEDNESDAY_0930 = "cron(30 9 ? * WED *)"


# UpdateMaintenanceWindow's recomputed NextExecutionTime is not guaranteed
# read-your-writes, so reads after it are polled.
def _error(fn):
    """Call fn(); return the ClientError Error dict (Code and Message) it raises.
    An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll(probe, predicate, timeout_s=90, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _parse_iso(value):
    """Parse SSM's ISO8601String timestamps (returned as strings, unlike DateTime members)."""
    assert isinstance(value, str) and value, f"expected an ISO8601 string, got {value!r}"
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
            try:
                parsed = dt.datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            raise AssertionError(f"unparseable ISO8601 timestamp: {value!r}")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A maintenance window's NextExecutionTime is computed from its cron, expands to a weekly
    schedule, is recomputed when the schedule changes and is withdrawn when disabled;
    an unknown window id is refused."""

    ssm = ctx.client("ssm")

    window_name = ctx.unique_name("sim2real-behav-mw-")
    created = ssm.create_maintenance_window(
        Name=window_name,
        Schedule=_MONDAY_0400,
        ScheduleTimezone="UTC",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    window_id = created["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))
    assert window_id.startswith("mw-"), f"unexpected WindowId shape: {window_id!r}"

    # --- NextExecutionTime is computed from the cron -------------------------
    got = ssm.get_maintenance_window(WindowId=window_id)
    assert got["Schedule"] == _MONDAY_0400, got
    assert got["ScheduleTimezone"] == "UTC", got
    assert got["Enabled"] is True, got
    assert "NextExecutionTime" in got, (
        "GetMaintenanceWindow must report a computed NextExecutionTime for an enabled "
        f"window, got keys {sorted(got)}"
    )
    next_exec = _parse_iso(got["NextExecutionTime"])
    now = dt.datetime.now(dt.timezone.utc)
    assert next_exec > now, (
        f"NextExecutionTime must be in the future: {next_exec.isoformat()} <= {now.isoformat()}"
    )
    assert next_exec <= now + dt.timedelta(days=8), (
        "a weekly cron's next execution must be within 8 days, got "
        f"{next_exec.isoformat()} (now {now.isoformat()})"
    )
    assert (next_exec.weekday(), next_exec.hour, next_exec.minute) == (0, 4, 0), (
        f"{_MONDAY_0400} must resolve to a Monday 04:00 UTC; got "
        f"{next_exec.isoformat()} (weekday={next_exec.weekday()})"
    )

    # DescribeMaintenanceWindows must agree with GetMaintenanceWindow.
    listed = [
        w
        for w in ssm.describe_maintenance_windows(
            Filters=[{"Key": "Name", "Values": [window_name]}]
        )["WindowIdentities"]
        if w["WindowId"] == window_id
    ]
    assert len(listed) == 1, f"the window must be findable by name filter, got {listed}"
    assert _parse_iso(listed[0]["NextExecutionTime"]) == next_exec, (
        "DescribeMaintenanceWindows and GetMaintenanceWindow must report the same "
        f"NextExecutionTime: {listed[0]['NextExecutionTime']!r} vs {got['NextExecutionTime']!r}"
    )

    # --- the schedule expands to a weekly series ----------------------------
    schedule = ssm.describe_maintenance_window_schedule(
        WindowId=window_id, MaxResults=5
    )["ScheduledWindowExecutions"]
    assert len(schedule) >= 3, (
        f"a weekly cron must expand to several occurrences, got {schedule}"
    )
    times = [_parse_iso(s["ExecutionTime"]) for s in schedule]
    assert times == sorted(times), (
        f"occurrences must be strictly increasing, got {[t.isoformat() for t in times]}"
    )
    assert len(set(times)) == len(times), (
        f"occurrences must not repeat, got {[t.isoformat() for t in times]}"
    )
    for occurrence in times:
        assert (occurrence.weekday(), occurrence.hour, occurrence.minute) == (0, 4, 0), (
            f"every occurrence of {_MONDAY_0400} must be Monday 04:00 UTC, got "
            f"{occurrence.isoformat()}"
        )
    for earlier, later in zip(times, times[1:]):
        assert later - earlier == dt.timedelta(days=7), (
            "consecutive weekly occurrences must be exactly 7 days apart, got "
            f"{earlier.isoformat()} -> {later.isoformat()}"
        )
    assert times[0] == next_exec, (
        "the first scheduled occurrence must equal NextExecutionTime: "
        f"{times[0].isoformat()} != {next_exec.isoformat()}"
    )
    assert all(s["WindowId"] == window_id for s in schedule), schedule

    # --- change the schedule; the computation must follow -------------------
    updated = ssm.update_maintenance_window(
        WindowId=window_id, Schedule=_WEDNESDAY_0930
    )
    assert updated["Schedule"] == _WEDNESDAY_0930, updated

    recomputed = _poll(
        lambda: ssm.get_maintenance_window(WindowId=window_id),
        lambda w: w.get("Schedule") == _WEDNESDAY_0930
        and "NextExecutionTime" in w
        and (
            lambda t: (t.weekday(), t.hour, t.minute) == (2, 9, 30)
        )(_parse_iso(w["NextExecutionTime"])),
    )
    new_next = _parse_iso(recomputed["NextExecutionTime"])
    assert (new_next.weekday(), new_next.hour, new_next.minute) == (2, 9, 30), (
        f"after the update, NextExecutionTime must be a Wednesday 09:30 UTC, got "
        f"{new_next.isoformat()}"
    )
    assert new_next != next_exec, (
        "NextExecutionTime must be recomputed, not carried over: it is still "
        f"{new_next.isoformat()}"
    )
    assert new_next > dt.datetime.now(dt.timezone.utc), new_next.isoformat()

    # The two reads are recomputed on DIFFERENT paths and do not flip together:
    # GetMaintenanceWindow.NextExecutionTime is recomputed synchronously with
    # UpdateMaintenanceWindow (the poll above returns on the first attempt), while
    # DescribeMaintenanceWindowSchedule keeps expanding the OLD cron for about a minute
    # afterwards (on real AWS, about 60 s of old-cron occurrences while NextExecutionTime
    # already read the new one). So the expansion is polled to the
    # updated cron with a bounded deadline; timing out is a hard failure, and the assertion --
    # every occurrence lands on the NEW cron -- is unchanged.
    new_schedule = [
        _parse_iso(s["ExecutionTime"])
        for s in _poll(
            lambda: ssm.describe_maintenance_window_schedule(
                WindowId=window_id, MaxResults=3
            )["ScheduledWindowExecutions"],
            lambda occurrences: bool(occurrences)
            and all(
                (lambda t: (t.weekday(), t.hour, t.minute) == (2, 9, 30))(
                    _parse_iso(s["ExecutionTime"])
                )
                for s in occurrences
            ),
            timeout_s=300,
            interval_s=5.0,
        )
    ]
    for occurrence in new_schedule:
        assert (occurrence.weekday(), occurrence.hour, occurrence.minute) == (2, 9, 30), (
            "DescribeMaintenanceWindowSchedule must reflect the updated cron, got "
            f"{occurrence.isoformat()}"
        )
    assert new_schedule[0] == new_next, (
        f"{new_schedule[0].isoformat()} != {new_next.isoformat()}"
    )

    # --- disabling the window must withdraw the computed time ---------------
    ssm.update_maintenance_window(WindowId=window_id, Enabled=False)
    disabled = _poll(
        lambda: ssm.get_maintenance_window(WindowId=window_id),
        lambda w: w.get("Enabled") is False,
    )
    assert "NextExecutionTime" not in disabled, (
        "a disabled window has no next execution and must not report one, got "
        f"{disabled.get('NextExecutionTime')!r}"
    )
    # Same asymmetry as above: GetMaintenanceWindow drops NextExecutionTime immediately, the
    # expansion catches up afterwards, so the withdrawal is polled rather than read once.
    assert (
        _poll(
            lambda: ssm.describe_maintenance_window_schedule(
                WindowId=window_id, MaxResults=3
            )["ScheduledWindowExecutions"],
            lambda occurrences: occurrences == [],
            timeout_s=300,
            interval_s=5.0,
        )
        == []
    ), "a disabled window must expand to no scheduled occurrences"

    # --- control: an unknown window id is refused ---------------------------
    unknown_window_id = "mw-00000000000000000"
    unknown = _error(lambda: ssm.get_maintenance_window(WindowId=unknown_window_id))
    assert unknown.get("Code") == "DoesNotExistException", (
        f"an unknown WindowId must be refused with DoesNotExistException, got {unknown!r}"
    )
    expected_message = f"Maintenance window {unknown_window_id} does not exist"
    assert unknown.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {unknown.get('Message')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

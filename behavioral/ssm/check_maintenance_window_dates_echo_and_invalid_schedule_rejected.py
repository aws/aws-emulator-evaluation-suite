"""maintenance-window-dates-echo-and-invalid-schedule-rejected."""

from __future__ import annotations

import datetime
import re

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-dates-echo-and-invalid-schedule-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]

_START = "2030-01-06T00:00:00Z"
_END = "2031-01-06T00:00:00Z"


def _error(fn):
    """The (code, message) ``fn`` raises; an unexpected success raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """GetMaintenanceWindow echoes StartDate, EndDate, ScheduleTimezone and every create field.

    The first execution falls after StartDate; a malformed cron Schedule is refused with
    ValidationException and its exact message, and no window is created.
    """
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-behav-mwdates-")
    window_id = ssm.create_maintenance_window(
        Name=name,
        Description="window with a start and end date",
        Schedule="cron(0 4 ? * MON *)",
        ScheduleTimezone="Etc/UTC",
        StartDate=_START,
        EndDate=_END,
        Duration=3,
        Cutoff=1,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))
    assert re.fullmatch(r"mw-[0-9a-f]{17}", window_id), (
        f"WindowId {window_id!r} has an unexpected form"
    )

    got = ssm.get_maintenance_window(WindowId=window_id)
    echoed = {
        key: got[key]
        for key in (
            "WindowId",
            "Name",
            "Description",
            "Schedule",
            "ScheduleTimezone",
            "StartDate",
            "EndDate",
            "Duration",
            "Cutoff",
            "AllowUnassociatedTargets",
            "Enabled",
        )
    }
    expected = {
        "WindowId": window_id,
        "Name": name,
        "Description": "window with a start and end date",
        "Schedule": "cron(0 4 ? * MON *)",
        "ScheduleTimezone": "Etc/UTC",
        "StartDate": _START,
        "EndDate": _END,
        "Duration": 3,
        "Cutoff": 1,
        "AllowUnassociatedTargets": True,
        "Enabled": True,
    }
    assert echoed == expected, f"GetMaintenanceWindow echoed {echoed!r}, expected {expected!r}"
    assert got["NextExecutionTime"] == "2030-01-07T04:00Z", (
        f"NextExecutionTime is {got['NextExecutionTime']!r}, expected the first Monday "
        "04:00 after StartDate"
    )
    assert isinstance(got["CreatedDate"], datetime.datetime), (
        f"CreatedDate is {got['CreatedDate']!r}"
    )
    assert got["ModifiedDate"] == got["CreatedDate"], (
        f"ModifiedDate {got['ModifiedDate']!r} differs from CreatedDate {got['CreatedDate']!r}"
    )

    bad_name = ctx.unique_name("sim2real-behav-mwbad-")
    bad_schedule = "cron(0 25 ? * MON *)"

    def create_bad():
        resp = ssm.create_maintenance_window(
            Name=bad_name,
            Schedule=bad_schedule,
            Duration=3,
            Cutoff=1,
            AllowUnassociatedTargets=True,
        )
        ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=resp["WindowId"]))
        return resp

    code, message = _error(create_bad)
    assert (code, message) == (
        "ValidationException",
        "Invalid CRON expression: error at position 1, details: '?' can only be specified "
        "for Day-of-Month or Day-of-Week.",
    ), f"CreateMaintenanceWindow with a malformed cron gave {code!r}: {message!r}"
    listed = ssm.describe_maintenance_windows(Filters=[{"Key": "Name", "Values": [bad_name]}])[
        "WindowIdentities"
    ]
    assert listed == [], f"a refused CreateMaintenanceWindow left {listed!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

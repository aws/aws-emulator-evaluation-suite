"""maintenance-window-update-and-schedule-describe."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "maintenance-window-update-and-schedule-describe"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateMaintenanceWindow changes are reflected in DescribeMaintenanceWindows and
    derived schedule occurrences via DescribeMaintenanceWindowSchedule."""
    ssm = ctx.client("ssm")
    name = ctx.unique_name("sim2real-mw-")
    window_id = ssm.create_maintenance_window(
        Name=name,
        Schedule="cron(0 12 * * ? *)",
        Duration=1,
        Cutoff=0,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real-behav-probe", "Value": name}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    identities = ssm.describe_maintenance_windows(Filters=[{"Key": "Name", "Values": [name]}])[
        "WindowIdentities"
    ]
    match = next(w for w in identities if w["WindowId"] == window_id)
    assert match["Enabled"] is True, match
    assert match["Schedule"] == "cron(0 12 * * ? *)", match

    ssm.update_maintenance_window(WindowId=window_id, Schedule="cron(0 18 * * ? *)", Enabled=False)
    identities = ssm.describe_maintenance_windows(Filters=[{"Key": "Name", "Values": [name]}])[
        "WindowIdentities"
    ]
    match = next(w for w in identities if w["WindowId"] == window_id)
    assert match["Enabled"] is False, match
    assert match["Schedule"] == "cron(0 18 * * ? *)", match

    # Re-enable so upcoming occurrences are computable, then verify the schedule
    # reflects the newly updated cron expression.
    ssm.update_maintenance_window(WindowId=window_id, Enabled=True)
    scheduled = ssm.describe_maintenance_window_schedule(WindowId=window_id)[
        "ScheduledWindowExecutions"
    ]
    assert len(scheduled) > 0, "no upcoming executions computed for an enabled window"
    for occurrence in scheduled:
        assert occurrence["WindowId"] == window_id, occurrence
        assert occurrence["Name"] == name, occurrence
        # ExecutionTime must reflect the newly updated 18:00 cron, not the old noon one.
        assert "18:00" in occurrence["ExecutionTime"], occurrence["ExecutionTime"]
        assert "12:00" not in occurrence["ExecutionTime"], occurrence["ExecutionTime"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

"""maintenance-window-task-update-and-schedule."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-task-update-and-schedule"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetMaintenanceWindowTask/Update* round-trip, and schedule/execution views."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            f"expected a ClientError, but the call succeeded and returned {result!r}"
        )

    def _create_maintenance_window():
        name = ctx.unique_name("sim2real-behav-probe-mw-")
        window_id = ssm.create_maintenance_window(
            Name=name,
            Schedule="cron(0 10 * * ? *)",
            Duration=2,
            Cutoff=1,
            AllowUnassociatedTargets=True,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )["WindowId"]
        ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))
        return window_id

    window_id = _create_maintenance_window()

    target_id = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}],
        Description="probe target",
    )["WindowTargetId"]

    task_id = ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        Targets=[{"Key": "WindowTargetIds", "Values": [target_id]}],
        TaskArn="AWS-RunShellScript",
        TaskType="RUN_COMMAND",
        MaxConcurrency="1",
        MaxErrors="1",
        Priority=1,
        Description="probe task",
    )["WindowTaskId"]

    task = ssm.get_maintenance_window_task(WindowId=window_id, WindowTaskId=task_id)
    assert task["MaxConcurrency"] == "1", task
    assert task["Priority"] == 1, task

    updated = ssm.update_maintenance_window_task(
        WindowId=window_id,
        WindowTaskId=task_id,
        MaxConcurrency="2",
        Description="probe task updated",
    )
    assert updated["MaxConcurrency"] == "2", updated
    task_after = ssm.get_maintenance_window_task(
        WindowId=window_id, WindowTaskId=task_id
    )
    assert task_after["MaxConcurrency"] == "2", task_after
    assert task_after["Description"] == "probe task updated", task_after
    # An unspecified field must not be reset by a partial update.
    assert task_after["MaxErrors"] == "1", task_after

    ssm.update_maintenance_window_target(
        WindowId=window_id,
        WindowTargetId=target_id,
        Description="probe target updated",
    )
    targets = ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    target = next(t for t in targets if t["WindowTargetId"] == target_id)
    assert target["Description"] == "probe target updated", target

    schedule = ssm.describe_maintenance_window_schedule(WindowId=window_id)[
        "ScheduledWindowExecutions"
    ]
    assert schedule, "an enabled cron window must project future executions"

    executions = ssm.describe_maintenance_window_executions(WindowId=window_id)[
        "WindowExecutions"
    ]
    assert executions == [], f"a never-run window must report no executions: {executions}"

    # Cancelling a non-existent window execution must be rejected.
    code, message = _error_code(
        lambda: ssm.cancel_maintenance_window_execution(
            WindowExecutionId=str(uuid.uuid4())
        )
    )
    assert code == "DoesNotExistException", code
    assert message == "Resource does not exist in the data store.", message

    ssm.deregister_task_from_maintenance_window(
        WindowId=window_id, WindowTaskId=task_id
    )
    tasks_after = ssm.describe_maintenance_window_tasks(WindowId=window_id)["Tasks"]
    assert all(t["WindowTaskId"] != task_id for t in tasks_after), tasks_after

    # A deregistered task is gone (specific not-found via an independent read, not just
    # absent from the list) and unusable (a mutation on the dead id is also rejected).
    get_code, get_message = _error_code(
        lambda: ssm.get_maintenance_window_task(
            WindowId=window_id, WindowTaskId=task_id
        )
    )
    assert get_code == "DoesNotExistException", get_code
    assert get_message == f"Maintenance window task {task_id} does not exist", get_message

    update_code, update_message = _error_code(
        lambda: ssm.update_maintenance_window_task(
            WindowId=window_id, WindowTaskId=task_id, Priority=9
        )
    )
    assert update_code == "DoesNotExistException", update_code
    assert update_message == f"Maintenance window task {task_id} does not exist", update_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

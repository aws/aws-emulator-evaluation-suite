"""maintenance-window-task-full-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "maintenance-window-task-full-lifecycle"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RegisterTaskWithMaintenanceWindow creates a task visible via Get/Describe,
    editable via Update, and removed via Deregister."""
    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            fn()
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        raise AssertionError(f"expected {fn} to raise, but it succeeded")

    window_id = _create_window(ctx)
    # A window target on a tag key only this check names, so the task targets no instance in the
    # account; a RUN_COMMAND task takes WindowTargetIds or InstanceIds, never a tag directly.
    target_tag = ctx.unique_name("tag:sim2real-mw-target-")
    target_id = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": target_tag, "Values": ["true"]}],
    )["WindowTargetId"]
    ctx.on_cleanup(lambda: _deregister_target_if_exists(ssm, window_id, target_id))

    registered = ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        TaskArn="AWS-RunShellScript",
        TaskType="RUN_COMMAND",
        Targets=[{"Key": "WindowTargetIds", "Values": [target_id]}],
        MaxConcurrency="1",
        MaxErrors="1",
        Priority=1,
        TaskInvocationParameters={"RunCommand": {"Parameters": {"commands": ["echo hi"]}}},
    )
    task_id = registered["WindowTaskId"]
    ctx.on_cleanup(lambda: _deregister_task_if_exists(ssm, window_id, task_id))

    fetched = ssm.get_maintenance_window_task(WindowId=window_id, WindowTaskId=task_id)
    assert fetched["TaskArn"] == "AWS-RunShellScript", fetched
    assert fetched["Priority"] == 1, fetched
    assert fetched["MaxConcurrency"] == "1", fetched

    described = ssm.describe_maintenance_window_tasks(WindowId=window_id)["Tasks"]
    task_ids = {t["WindowTaskId"] for t in described}
    assert task_id in task_ids, (task_id, task_ids)

    ssm.update_maintenance_window_task(WindowId=window_id, WindowTaskId=task_id, Priority=5)
    refetched = ssm.get_maintenance_window_task(WindowId=window_id, WindowTaskId=task_id)
    assert refetched["Priority"] == 5, refetched
    # Fields not touched by the partial update remain intact.
    assert refetched["TaskArn"] == "AWS-RunShellScript", refetched
    assert refetched["MaxConcurrency"] == "1", refetched

    ssm.deregister_task_from_maintenance_window(WindowId=window_id, WindowTaskId=task_id)
    described = ssm.describe_maintenance_window_tasks(WindowId=window_id)["Tasks"]
    task_ids = {t["WindowTaskId"] for t in described}
    assert task_id not in task_ids, (task_id, task_ids)

    # The deregistered id is gone, not just absent from the list: an independent
    # read raises the specific not-found code, and a mutation on it fails the same
    # way. (Deregister itself is idempotent on real AWS -- calling it a second time
    # on an already-gone task succeeds rather than raising, which is why the
    # mutation probe below is Update, not a repeated Deregister.)
    get_code, get_message = _error_code(
        lambda: ssm.get_maintenance_window_task(WindowId=window_id, WindowTaskId=task_id)
    )
    assert get_code == "DoesNotExistException", get_code
    assert get_message == f"Maintenance window task {task_id} does not exist", get_message
    update_dead_code, update_dead_message = _error_code(
        lambda: ssm.update_maintenance_window_task(WindowId=window_id, WindowTaskId=task_id, Priority=9)
    )
    assert update_dead_code == "DoesNotExistException", update_dead_code
    assert update_dead_message == f"Maintenance window task {task_id} does not exist", update_dead_message


def _create_window(ctx) -> str:
    ssm = ctx.client("ssm")
    window_id = ssm.create_maintenance_window(
        Name=ctx.unique_name("sim2real-mw-"),
        Schedule="cron(0 0 ? * SUN *)",
        Duration=2,
        Cutoff=1,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))
    return window_id


def _deregister_target_if_exists(ssm, window_id: str, target_id: str) -> None:
    try:
        ssm.deregister_target_from_maintenance_window(WindowId=window_id, WindowTargetId=target_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DoesNotExistException":
            raise


def _deregister_task_if_exists(ssm, window_id: str, task_id: str) -> None:
    try:
        ssm.deregister_task_from_maintenance_window(WindowId=window_id, WindowTaskId=task_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DoesNotExistException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

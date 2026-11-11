"""deregister-target-rejects-when-task-references-it."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-target-rejects-when-task-references-it"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterTargetFromMaintenanceWindow(Safe=True) rejects a target a task still references and
    leaves it registered; once the task is removed the same call succeeds and the target is gone."""

    ssm = ctx.client("ssm")

    def _error_code(fn):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(
            f"expected a rejection, but the call SUCCEEDED and returned {result!r}"
        )

    def _registered_target_ids(window_id):
        return {
            t["WindowTargetId"]
            for t in ssm.describe_maintenance_window_targets(WindowId=window_id)[
                "Targets"
            ]
        }

    def _create_maintenance_window():
        name = ctx.unique_name("sim2real-behav-probe-mw-")
        window_id = ssm.create_maintenance_window(
            Name=name,
            Schedule="cron(0 10 * * ? *)",
            Duration=2,
            Cutoff=1,
            AllowUnassociatedTargets=True,
            Tags=[{"Key": "sim2real-behav-probe", "Value": name}],
        )["WindowId"]
        ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))
        return window_id

    window_id = _create_maintenance_window()

    target_resp = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": ["i-0123456789abcdef0"]}],
    )
    target_id = target_resp["WindowTargetId"]

    task_resp = ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        Targets=[{"Key": "WindowTargetIds", "Values": [target_id]}],
        TaskArn="AWS-RunShellScript",
        TaskType="RUN_COMMAND",
        MaxConcurrency="1",
        MaxErrors="1",
    )
    task_id = task_resp["WindowTaskId"]

    def _safe_deregister_target():
        return ssm.deregister_target_from_maintenance_window(
            WindowId=window_id, WindowTargetId=target_id, Safe=True
        )

    code, message = _error_code(_safe_deregister_target)
    assert code == "TargetInUseException", (
        f"expected TargetInUseException while the task still references the "
        f"target, got {code!r}"
    )
    assert message == (
        f"This Target cannot be deregistered because it is still referenced in Task: {task_id}"
    ), message

    still_registered = _registered_target_ids(window_id)
    assert target_id in still_registered, (
        f"rejected Safe deregister must leave the target registered; "
        f"{target_id!r} missing from {still_registered!r}"
    )

    ssm.deregister_task_from_maintenance_window(
        WindowId=window_id, WindowTaskId=task_id
    )

    # Restore: the identical Safe=True call now succeeds once the referencing task is gone.
    _safe_deregister_target()

    remaining = _registered_target_ids(window_id)
    assert target_id not in remaining, (
        f"target {target_id!r} must be gone after the restored Safe deregister "
        f"succeeds, still present in {remaining!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

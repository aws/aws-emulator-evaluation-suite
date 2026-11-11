"""deregister-target-in-use-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-target-in-use-rejected"
GROUP = "state-machine"
SERVICES = ["ssm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterTargetFromMaintenanceWindow with Safe=True on a target a task references fails with
    TargetInUseException naming the task and leaves the target registered; after the task is
    deregistered the same call succeeds."""
    ssm = ctx.client("ssm")
    window_name = ctx.unique_name("sim2real-mw-inuse-")

    window_id = ssm.create_maintenance_window(
        Name=window_name,
        Schedule="rate(30 days)",
        Duration=1,
        Cutoff=0,
        AllowUnassociatedTargets=True,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["WindowId"]
    ctx.on_cleanup(lambda: ssm.delete_maintenance_window(WindowId=window_id))

    target_id = ssm.register_target_with_maintenance_window(
        WindowId=window_id,
        ResourceType="INSTANCE",
        Targets=[{"Key": "InstanceIds", "Values": ["i-00000000000000000"]}],
    )["WindowTargetId"]

    task_id = ssm.register_task_with_maintenance_window(
        WindowId=window_id,
        Targets=[{"Key": "WindowTargetIds", "Values": [target_id]}],
        TaskArn="AWS-RunShellScript",
        TaskType="RUN_COMMAND",
        MaxConcurrency="1",
        MaxErrors="1",
    )["WindowTaskId"]

    code, message = _error(
        lambda: ssm.deregister_target_from_maintenance_window(
            WindowId=window_id, WindowTargetId=target_id, Safe=True
        )
    )
    assert code == "TargetInUseException", code
    assert message == (
        f"This Target cannot be deregistered because it is still referenced in Task: {task_id}"
    ), message

    still_registered = {
        t["WindowTargetId"]
        for t in ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    }
    assert target_id in still_registered

    # Restore: removing the referencing task first lets the IDENTICAL Safe=True call
    # succeed, proving the rejection was about the in-use conflict and not a blanket
    # failure of the Safe deregister path.
    ssm.deregister_task_from_maintenance_window(WindowId=window_id, WindowTaskId=task_id)
    ssm.deregister_target_from_maintenance_window(
        WindowId=window_id, WindowTargetId=target_id, Safe=True
    )

    remaining = {
        t["WindowTargetId"]
        for t in ssm.describe_maintenance_window_targets(WindowId=window_id)["Targets"]
    }
    assert target_id not in remaining


def _error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, so an
    emulator that accepts what AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
